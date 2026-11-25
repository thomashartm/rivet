//! Dependency resolution and the lazy activation index
//! (ARCHITECTURE.md §4.4, §4.5, §5.7).
//!
//! This module is pure logic: manifests in, plain data out. It does no I/O
//! and loads no code. The extension host calls it.
//!
//! - [`resolve`] decides for each extension whether it is `Resolved` or
//!   `Rejected`, and gives the activation order of the resolved extensions.
//! - [`ActivationIndex`] answers which resolved extensions an event activates.
//!
//! Each extension is present in one version only. Thus resolution is a check
//! plus an ordering, not a search for versions.
//!
//! ```
//! use rivet_core::resolve::{ActivationIndex, ActivationTrigger, resolve};
//! use rivet_sdk::manifest::{Manifest, Version};
//!
//! let auth = Manifest::parse("id = \"acme.auth\"\nversion = \"2.1.0\"\nsdk = \"^0.1\"\n")?;
//! let postgres = Manifest::parse(
//!     r#"
//!     id = "acme.postgres"
//!     version = "1.0.0"
//!     sdk = "^0.1"
//!
//!     [dependencies]
//!     "acme.auth" = "^2"
//!
//!     [[activation]]
//!     on = "connection"
//!     type = "postgres"
//!     "#,
//! )?;
//!
//! let resolution = resolve(&[postgres, auth], &Version::new(0, 1, 0));
//! let index = ActivationIndex::new(&resolution);
//! let plan = index.plan(ActivationTrigger::Connection("postgres"), true);
//! let ids: Vec<&str> = plan.activate.iter().map(|id| id.as_str()).collect();
//! assert_eq!(ids, ["acme.auth", "acme.postgres"]);
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```

use rivet_sdk::error::Error;
use rivet_sdk::manifest::{
    ActivationEvent, ExtensionId, ExtensionPoint, Manifest, Version, VersionReq,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The result of resolution for one extension (§4.4 state diagram).
#[derive(Debug)]
pub enum Outcome {
    /// The SDK range and all dependencies are satisfied. The extension can
    /// activate.
    Resolved,
    /// The extension must not be loaded.
    Rejected {
        /// Why the extension is rejected: an error of the category `user`.
        /// The message names the extensions and the version ranges.
        reason: Error,
    },
}

/// The result of [`resolve`].
#[derive(Debug, Default)]
pub struct Resolution {
    outcomes: BTreeMap<ExtensionId, Outcome>,
    /// The manifests of the resolved extensions, in activation order.
    resolved: Vec<Manifest>,
}

impl Resolution {
    /// Returns the outcome of each extension id in the input, sorted by id.
    pub fn outcomes(&self) -> &BTreeMap<ExtensionId, Outcome> {
        &self.outcomes
    }

    /// Returns the resolved extensions in activation order: each extension
    /// comes after all its dependencies. Extensions that do not depend on
    /// each other are sorted by id.
    pub fn activation_order(&self) -> impl DoubleEndedIterator<Item = &ExtensionId> {
        self.resolved.iter().map(|manifest| &manifest.id)
    }

    /// Returns the resolved extensions in shutdown order: the reverse of
    /// [`activation_order`](Self::activation_order) (§5.7).
    pub fn shutdown_order(&self) -> impl Iterator<Item = &ExtensionId> {
        self.activation_order().rev()
    }
}

/// The largest number of extensions that one rejection reason names as
/// conflict parties.
pub const MAX_CONFLICT_PARTIES: usize = 5;

/// The largest number of characters of one version range that a rejection
/// reason contains. A longer range is cut and gets `...` at the end.
pub const MAX_RANGE_CHARS: usize = 64;

/// Returns `range` cut to [`MAX_RANGE_CHARS`] characters.
fn cut(range: &str) -> String {
    // Not `logging::cut`: that one counts bytes and marks with `…`. The
    // public limit here is in characters and the mark is `...`.
    match range.char_indices().nth(MAX_RANGE_CHARS) {
        Some((end, _)) => format!("{}...", &range[..end]),
        None => range.to_owned(),
    }
}

/// Resolves the dependencies of `manifests` for a host with the SDK version
/// `host_sdk` (§4.5).
///
/// The function never fails as a whole. One rejected extension does not stop
/// the other extensions from resolving. The result is the same for the same
/// set of manifests in any order.
///
/// An extension is rejected for the first of these reasons that applies:
///
/// 1. Two or more manifests have its id. All of them are rejected.
/// 2. It is in a dependency cycle. The reason names the cycle.
/// 3. Its SDK range does not include `host_sdk`.
/// 4. A dependency is not present.
/// 5. A dependency is present in a version outside the range. An extension
///    whose range includes the present version is not rejected for this.
///
///    The reason also names the conflicts: each other extension that depends
///    on the same extension with a conflicting range, and its range, sorted
///    by id.
///    - Two ranges conflict when no release version satisfies both. Thus
///      `^1` and `^2` conflict; `^1`, `^1.0` and `>=1.0.0, <2.0.0` do not,
///      and `^1` and `^1.2` do not.
///    - Limit: versions with a pre-release tag are not tried. Two ranges
///      that have only pre-release versions in common are named as a
///      conflict.
///    - An extension that is rejected for another reason is not named.
///      Reason 4 names no conflicts: a dependency that is not present has
///      no version that a range can exclude.
///    - A range longer than [`MAX_RANGE_CHARS`] characters is cut, in this
///      reason and in reasons 3 and 4.
///    - At most [`MAX_CONFLICT_PARTIES`] extensions are named. The reason
///      gives the number of the others.
///    - Cost: for each extension with this reason, one range comparison
///      with each other extension that depends on the same extension. For
///      `n` such dependents of one extension, that is `n * n` comparisons.
///      Only the named extensions are written as text.
/// 6. A dependency is rejected.
///
/// Reasons 4 to 6 are checked for one dependency after the other, sorted by
/// id.
pub fn resolve(manifests: &[Manifest], host_sdk: &Version) -> Resolution {
    let reject = |message: String| Outcome::Rejected {
        reason: Error::user(message),
    };

    let mut by_id: BTreeMap<&ExtensionId, Vec<&Manifest>> = BTreeMap::new();
    for manifest in manifests {
        by_id.entry(&manifest.id).or_default().push(manifest);
    }
    let mut outcomes = BTreeMap::new();
    // The extensions with exactly one manifest. Only these can resolve.
    let mut unique: BTreeMap<&ExtensionId, &Manifest> = BTreeMap::new();
    for (&id, group) in &by_id {
        if let [manifest] = group[..] {
            unique.insert(id, manifest);
            continue;
        }
        let versions: BTreeSet<&Version> = group.iter().map(|manifest| &manifest.version).collect();
        let versions: Vec<String> = versions.iter().map(ToString::to_string).collect();
        let message = format!(
            "extension `{id}` has {} manifests (versions {}); only one version of an extension \
             can be loaded",
            group.len(),
            versions.join(", ")
        );
        outcomes.insert(id.clone(), reject(message));
    }

    // Topological sort (Kahn). `waiting` counts the dependencies of an
    // extension that are not sorted yet. The smallest id goes first.
    let mut waiting: BTreeMap<&ExtensionId, usize> = unique
        .iter()
        .map(|(&id, manifest)| {
            let present = |dependency: &&ExtensionId| unique.contains_key(*dependency);
            (id, manifest.dependencies.keys().filter(present).count())
        })
        .collect();
    let mut ready: BTreeSet<&ExtensionId> = waiting
        .iter()
        .filter(|&(_, &count)| count == 0)
        .map(|(&id, _)| id)
        .collect();
    let mut sorted = Vec::with_capacity(unique.len());
    while let Some(id) = ready.pop_first() {
        sorted.push(id);
        for (&dependent, manifest) in &unique {
            if !manifest.dependencies.contains_key(id) {
                continue;
            }
            if let Some(count) = waiting.get_mut(dependent) {
                *count -= 1;
                if *count == 0 {
                    ready.insert(dependent);
                }
            }
        }
    }
    // An extension that could not be sorted is in a cycle or depends on one.
    let stuck = |id: &ExtensionId| waiting.get(id).is_some_and(|&count| count > 0);
    let unsorted = unique.keys().copied().filter(|&id| stuck(id));

    let mut resolved = Vec::new();
    // (dependent, dependency): the range rejects the present version.
    let mut mismatches: BTreeSet<(&ExtensionId, &ExtensionId)> = BTreeSet::new();
    for id in sorted.iter().copied().chain(unsorted) {
        let Some(&manifest) = unique.get(id) else {
            continue;
        };
        let is_rejected = |dependency: &ExtensionId| {
            stuck(dependency) || matches!(outcomes.get(dependency), Some(Outcome::Rejected { .. }))
        };
        let outcome = if let Some(cycle) = find_cycle(id, &unique, stuck) {
            let path: Vec<String> = cycle
                .iter()
                .chain(cycle.first())
                .map(|member| format!("`{member}`"))
                .collect();
            reject(format!(
                "extension `{id}` is in the dependency cycle {}",
                path.join(" -> ")
            ))
        } else if !manifest.sdk.matches(host_sdk) {
            reject(format!(
                "extension `{id}` supports the SDK versions `{}`, but the host has the SDK \
                 version {host_sdk}",
                cut(&manifest.sdk.to_string())
            ))
        } else {
            manifest
                .dependencies
                .iter()
                .find_map(|(dependency, range)| match unique.get(dependency) {
                    None if !outcomes.contains_key(dependency) => Some(format!(
                        "extension `{id}` depends on `{dependency}` `{}`, but \
                         `{dependency}` is not present",
                        cut(&range.to_string())
                    )),
                    Some(found) if !range.matches(&found.version) => {
                        mismatches.insert((id, dependency));
                        Some(format!(
                            "extension `{id}` depends on `{dependency}` `{}`, but \
                             `{dependency}` {} is present",
                            cut(&range.to_string()),
                            found.version
                        ))
                    }
                    _ => is_rejected(dependency).then(|| {
                        format!("extension `{id}` depends on `{dependency}`, which is rejected")
                    }),
                })
                .map_or(Outcome::Resolved, reject)
        };
        if matches!(outcome, Outcome::Resolved) {
            resolved.push(manifest.clone());
        }
        outcomes.insert(id.clone(), outcome);
    }

    // The conflict parties of reason 5. This needs the outcome of each
    // extension, so it comes after the loop.
    for &(id, dependency) in &mismatches {
        let (Some(manifest), Some(Outcome::Rejected { reason })) =
            (unique.get(id), outcomes.get(id))
        else {
            continue;
        };
        let Some(range) = manifest.dependencies.get(dependency) else {
            continue;
        };
        let mut parties = unique
            .values()
            .filter(|other| other.id != *id)
            .filter_map(|other| {
                let other_range = other.dependencies.get(dependency)?;
                let takes_part = matches!(outcomes.get(&other.id), Some(Outcome::Resolved)) || {
                    count_step();
                    mismatches.contains(&(&other.id, dependency))
                };
                (takes_part && ranges_conflict(range, other_range)).then_some((other, other_range))
            });
        // Only the named parties become text. The others are counted.
        let named: Vec<String> = parties
            .by_ref()
            .take(MAX_CONFLICT_PARTIES)
            .map(|(other, other_range)| {
                count_text();
                format!(
                    "extension `{}`, which depends on `{dependency}` `{}`",
                    other.id,
                    cut(&other_range.to_string())
                )
            })
            .collect();
        if named.is_empty() {
            continue;
        }
        let more = parties.count();
        let mut message = format!(
            "{}; this is a conflict with {}",
            reason.message(),
            named.join(" and ")
        );
        if more > 0 {
            message += &format!(" and {more} more extensions");
        }
        outcomes.insert(id.clone(), reject(message));
    }
    Resolution { outcomes, resolved }
}

#[cfg(test)]
thread_local! {
    /// The number of lookups in the conflict pass of [`resolve`] on this
    /// thread. A test uses it to check the cost without a clock.
    static CONFLICT_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one lookup of the conflict pass. Does nothing outside tests.
fn count_step() {
    #[cfg(test)]
    CONFLICT_STEPS.set(CONFLICT_STEPS.get() + 1);
}

#[cfg(test)]
thread_local! {
    /// The number of conflict parties that the conflict pass of [`resolve`]
    /// wrote as text on this thread.
    static CONFLICT_TEXTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one conflict party that is written as text. Does nothing outside
/// tests.
fn count_text() {
    #[cfg(test)]
    CONFLICT_TEXTS.set(CONFLICT_TEXTS.get() + 1);
}

/// `true` if no release version satisfies both ranges.
///
/// Versions with a pre-release tag are not tried: two ranges that have only
/// pre-release versions in common are reported as a conflict.
fn ranges_conflict(a: &VersionReq, b: &VersionReq) -> bool {
    // If a version satisfies both ranges, the smallest such version is 0.0.0,
    // the version of a comparator, or the next patch, minor or major version
    // after it (`>1.2.3`, `>1.2`, `>1`). To try these is enough.
    let after = |number: u64| number.saturating_add(1);
    let comparators = a.comparators.iter().chain(&b.comparators);
    let mut candidates = comparators
        .flat_map(|comparator| {
            let major = comparator.major;
            let minor = comparator.minor.unwrap_or(0);
            let patch = comparator.patch.unwrap_or(0);
            [
                Version::new(major, minor, patch),
                Version::new(major, minor, after(patch)),
                Version::new(major, after(minor), 0),
                Version::new(after(major), 0, 0),
            ]
        })
        .chain([Version::new(0, 0, 0)]);
    !candidates.any(|version| a.matches(&version) && b.matches(&version))
}

/// Finds the shortest dependency cycle through `start`. The result starts at
/// the smallest id of the cycle and does not repeat it at the end.
fn find_cycle<'a>(
    start: &'a ExtensionId,
    unique: &BTreeMap<&'a ExtensionId, &'a Manifest>,
    stuck: impl Fn(&ExtensionId) -> bool,
) -> Option<Vec<&'a ExtensionId>> {
    if !stuck(start) {
        return None;
    }
    // Breadth-first search along the dependencies. `found_from` maps an
    // extension to the extension that the search reached it from.
    let mut found_from: BTreeMap<&ExtensionId, &ExtensionId> = BTreeMap::new();
    let mut queue = VecDeque::from([start]);
    while let Some(id) = queue.pop_front() {
        let Some(manifest) = unique.get(id) else {
            continue;
        };
        for dependency in manifest.dependencies.keys() {
            if dependency == start {
                let mut path = vec![id];
                while let Some(&previous) = path.last().and_then(|last| found_from.get(last)) {
                    path.push(previous);
                }
                path.reverse();
                let smallest = path.iter().enumerate().min_by_key(|&(_, &member)| member);
                let offset = smallest.map_or(0, |(position, _)| position);
                path.rotate_left(offset);
                return Some(path);
            }
            if stuck(dependency) && !found_from.contains_key(dependency) {
                found_from.insert(dependency, id);
                queue.push_back(dependency);
            }
        }
    }
    None
}

/// An event that can activate extensions (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationTrigger<'a> {
    /// The first use of an extension point.
    ExtensionPoint(ExtensionPoint),
    /// The invocation of the command with this name.
    Command(&'a str),
    /// The opening of a connection of this type, for example `postgres`.
    Connection(&'a str),
}

impl ActivationTrigger<'_> {
    /// Returns `true` when an activation event of `manifest` matches.
    fn matches(self, manifest: &Manifest) -> bool {
        manifest.activation.iter().any(|event| match (event, self) {
            (ActivationEvent::ExtensionPoint, Self::ExtensionPoint(point)) => manifest
                .contributes
                .iter()
                .any(|contribution| contribution.kind == point),
            (ActivationEvent::Command { command }, Self::Command(name)) => command == name,
            (ActivationEvent::Connection { connection_type }, Self::Connection(name)) => {
                connection_type == name
            }
            _ => false,
        })
    }
}

/// The answer of [`ActivationIndex::plan`].
#[derive(Debug, Default)]
pub struct ActivationPlan {
    /// The extensions to activate, in order: each extension comes after all
    /// its dependencies. Each extension is listed one time. The host skips
    /// the extensions that are active already.
    pub activate: Vec<ExtensionId>,
    /// The extensions that match the event but cannot activate, each with
    /// the reason: an error of the category `policy`. This occurs in a
    /// headless process when the extension depends on an extension with
    /// `requires_ui = true`.
    pub blocked: BTreeMap<ExtensionId, Error>,
}

struct Entry {
    manifest: Manifest,
    /// Positions of the direct dependencies. They are all smaller than the
    /// position of this entry.
    dependencies: Vec<usize>,
    /// Position of an extension with `requires_ui = true` that this extension
    /// needs: itself or a direct or indirect dependency.
    needs_ui: Option<usize>,
}

/// An index of the resolved extensions that answers which extensions an event
/// activates (§4.4). Rejected extensions are not in the index.
pub struct ActivationIndex {
    /// In activation order.
    entries: Vec<Entry>,
}

impl ActivationIndex {
    /// Creates the index from the resolved extensions of `resolution`.
    pub fn new(resolution: &Resolution) -> Self {
        let positions: BTreeMap<&ExtensionId, usize> = resolution
            .activation_order()
            .enumerate()
            .map(|(position, id)| (id, position))
            .collect();
        let mut entries: Vec<Entry> = Vec::with_capacity(resolution.resolved.len());
        for manifest in &resolution.resolved {
            let dependencies: Vec<usize> = manifest
                .dependencies
                .keys()
                .filter_map(|dependency| positions.get(dependency).copied())
                .collect();
            let needs_ui = if manifest.requires_ui {
                Some(entries.len())
            } else {
                dependencies
                    .iter()
                    .find_map(|&dependency| entries.get(dependency)?.needs_ui)
            };
            entries.push(Entry {
                manifest: manifest.clone(),
                dependencies,
                needs_ui,
            });
        }
        Self { entries }
    }

    /// Returns the extensions to activate for `trigger`.
    ///
    /// An extension is selected only when one of its activation events
    /// matches `trigger`:
    ///
    /// - `extension-point` matches [`ActivationTrigger::ExtensionPoint`] for
    ///   each extension point the extension contributes.
    /// - `command` matches [`ActivationTrigger::Command`] with the same name.
    /// - `connection` matches [`ActivationTrigger::Connection`] with the
    ///   same type.
    ///
    /// The dependencies of a selected extension are listed before it, also
    /// when they have no matching activation event.
    ///
    /// When `headless` is `true`:
    ///
    /// - An extension with `requires_ui = true` is not selected and is not
    ///   reported.
    /// - An extension that depends on such an extension, directly or
    ///   indirectly, cannot activate. It is reported in
    ///   [`ActivationPlan::blocked`].
    pub fn plan(&self, trigger: ActivationTrigger<'_>, headless: bool) -> ActivationPlan {
        let mut plan = ActivationPlan::default();
        let mut needed = vec![false; self.entries.len()];
        for (position, entry) in self.entries.iter().enumerate() {
            if !trigger.matches(&entry.manifest) {
                continue;
            }
            match entry.needs_ui.filter(|_| headless) {
                None => needed[position] = true,
                Some(ui) if ui == position => {}
                Some(ui) => {
                    let id = &entry.manifest.id;
                    let ui = &self.entries[ui].manifest.id;
                    let reason = Error::policy(format!(
                        "extension `{id}` cannot activate in a headless process: it depends on \
                         `{ui}`, which has `requires_ui = true`"
                    ));
                    plan.blocked.insert(id.clone(), reason);
                }
            }
        }
        // Dependencies have smaller positions, so one pass from the end
        // reaches the indirect dependencies too.
        for (position, entry) in self.entries.iter().enumerate().rev() {
            if needed[position] {
                for &dependency in &entry.dependencies {
                    needed[dependency] = true;
                }
            }
        }
        let needed_entries = self
            .entries
            .iter()
            .zip(needed)
            .filter(|(_, needed)| *needed);
        plan.activate = needed_entries
            .map(|(entry, _)| entry.manifest.id.clone())
            .collect();
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_sdk::error::ErrorCategory;

    /// A manifest with the SDK range `^0.1`. `top` holds more top-level
    /// fields, `tables` holds `[[contributes]]` and `[[activation]]` tables.
    fn ext_with(
        id: &str,
        version: &str,
        deps: &[(&str, &str)],
        top: &str,
        tables: &str,
    ) -> Manifest {
        let mut text = format!(
            "id = \"{id}\"\nversion = \"{version}\"\nsdk = \"^0.1\"\n{top}\n[dependencies]\n"
        );
        for (dependency, range) in deps {
            text += &format!("\"{dependency}\" = \"{range}\"\n");
        }
        text += tables;
        Manifest::parse(&text).expect("valid manifest")
    }

    fn ext(id: &str, version: &str, deps: &[(&str, &str)]) -> Manifest {
        ext_with(id, version, deps, "", "")
    }

    fn on_command(id: &str, deps: &[(&str, &str)], top: &str) -> Manifest {
        let tables = format!("[[activation]]\non = \"command\"\ncommand = \"{id}.run\"\n");
        ext_with(id, "1.0.0", deps, top, &tables)
    }

    const UI: &str = "requires_ui = true\n";

    fn resolve_all(manifests: &[Manifest]) -> Resolution {
        resolve(manifests, &Version::new(0, 1, 0))
    }

    fn is_resolved(resolution: &Resolution, id: &str) -> bool {
        let id: ExtensionId = id.parse().expect("valid id");
        matches!(resolution.outcomes().get(&id), Some(Outcome::Resolved))
    }

    /// The message of the rejection of `id`. Checks the category and that the
    /// message contains each expected part.
    fn rejected(resolution: &Resolution, id: &str, parts: &[&str]) -> String {
        let key: ExtensionId = id.parse().expect("valid id");
        let Some(Outcome::Rejected { reason }) = resolution.outcomes().get(&key) else {
            panic!("`{id}` must be rejected: {:?}", resolution.outcomes());
        };
        assert_eq!(reason.category(), ErrorCategory::User);
        for part in parts {
            assert!(
                reason.message().contains(part),
                "`{part}` is not in the message:\n{}",
                reason.message()
            );
        }
        reason.message().to_owned()
    }

    fn order(resolution: &Resolution) -> Vec<&str> {
        resolution
            .activation_order()
            .map(ExtensionId::as_str)
            .collect()
    }

    fn activate(plan: &ActivationPlan) -> Vec<&str> {
        plan.activate.iter().map(ExtensionId::as_str).collect()
    }

    #[test]
    fn each_extension_gets_an_outcome() {
        let resolution = resolve_all(&[ext("a", "1.0.0", &[]), ext("b", "1.0.0", &[("x", "^1")])]);
        assert_eq!(resolution.outcomes().len(), 2);
        assert!(is_resolved(&resolution, "a"));
        rejected(&resolution, "b", &[]);
    }

    #[test]
    fn rejects_sdk_range_that_excludes_the_host() {
        let manifests = [ext("a", "1.0.0", &[]), ext("b", "1.0.0", &[])];
        let resolution = resolve(&manifests, &Version::new(0, 2, 0));
        rejected(&resolution, "a", &["`a`", "`^0.1`", "0.2.0"]);
        assert!(order(&resolution).is_empty());
        assert!(is_resolved(
            &resolve(&manifests, &Version::new(0, 1, 7)),
            "a"
        ));
    }

    #[test]
    fn dependency_needs_a_present_extension_in_the_range() {
        let resolution = resolve_all(&[
            ext("a", "1.0.0", &[("lib", "^1.2")]),
            ext("b", "1.0.0", &[("lib", "^2")]),
            ext("lib", "1.5.0", &[]),
        ]);
        assert!(is_resolved(&resolution, "a"));
        assert!(is_resolved(&resolution, "lib"));
        rejected(&resolution, "b", &["`b`", "`lib`", "`^2`", "1.5.0"]);
    }

    #[test]
    fn missing_dependency_names_extension_dependency_and_range() {
        let resolution = resolve_all(&[ext("a", "1.0.0", &[("gone", ">=1.2, <2")])]);
        rejected(
            &resolution,
            "a",
            &["`a`", "`gone`", "`>=1.2, <2`", "not present"],
        );
    }

    #[test]
    fn conflicting_ranges_name_both_extensions_and_both_ranges() {
        let resolution = resolve_all(&[
            ext("a", "1.0.0", &[("lib", "^1")]),
            ext("b", "1.0.0", &[("lib", "^2")]),
            ext("lib", "1.5.0", &[]),
        ]);
        rejected(
            &resolution,
            "b",
            &["`b`", "`^2`", "conflict", "`a`", "`^1`", "`lib`"],
        );
        assert!(is_resolved(&resolution, "a"));
    }

    #[test]
    fn conflicting_ranges_are_named_when_no_range_includes_the_present_version() {
        let resolution = resolve_all(&[
            ext("a", "1.0.0", &[("lib", "^1")]),
            ext("b", "1.0.0", &[("lib", "^2")]),
            ext("lib", "3.0.0", &[]),
        ]);
        rejected(
            &resolution,
            "a",
            &["`a`", "`^1`", "3.0.0", "conflict", "`b`", "`^2`", "`lib`"],
        );
        rejected(
            &resolution,
            "b",
            &["`b`", "`^2`", "3.0.0", "conflict", "`a`", "`^1`", "`lib`"],
        );
    }

    #[test]
    fn conflict_of_three_dependents_names_each_other_dependent_in_id_order() {
        let manifests = [
            ext("c", "1.0.0", &[("lib", "^3")]),
            ext("a", "1.0.0", &[("lib", "^1")]),
            ext("b", "1.0.0", &[("lib", "^2")]),
            // The same range as `a`: not a conflict with `a`.
            ext("d", "1.0.0", &[("lib", "^1")]),
            ext("lib", "2.0.0", &[]),
        ];
        let resolution = resolve_all(&manifests);
        assert!(is_resolved(&resolution, "b"));
        let b = "extension `b`, which depends on `lib` `^2`";
        let c = "extension `c`, which depends on `lib` `^3`";
        let a = "extension `a`, which depends on `lib` `^1`";
        let d = "extension `d`, which depends on `lib` `^1`";
        let message = rejected(&resolution, "a", &[&format!("conflict with {b} and {c}")]);
        assert!(!message.contains("`d`"), "{message}");
        rejected(&resolution, "d", &[&format!("conflict with {b} and {c}")]);
        rejected(
            &resolution,
            "c",
            &[&format!("conflict with {a} and {b} and {d}")],
        );
    }

    /// R-46: `^1`, `^1.0` and `>=1.0.0, <2.0.0` are one range in three
    /// spellings, and `^1.2` has versions in common with them.
    #[test]
    fn ranges_with_a_common_version_are_not_a_conflict() {
        let dependents = |lib: &str| {
            resolve_all(&[
                ext("a", "1.0.0", &[("lib", "^1")]),
                ext("b", "1.0.0", &[("lib", "^1.0")]),
                ext("c", "1.0.0", &[("lib", ">=1.0.0, <2.0.0")]),
                ext("d", "1.0.0", &[("lib", "^1.2")]),
                ext("lib", lib, &[]),
            ])
        };
        let resolution = dependents("3.0.0");
        for id in ["a", "b", "c", "d"] {
            let message = rejected(&resolution, id, &["3.0.0 is present"]);
            assert!(!message.contains("conflict"), "{message}");
        }
        let resolution = dependents("1.1.0");
        let message = rejected(&resolution, "d", &["1.1.0 is present"]);
        assert!(!message.contains("conflict"), "{message}");
    }

    #[test]
    fn ranges_conflict_when_no_release_version_satisfies_both() {
        let conflict = |a: &str, b: &str| {
            let (a, b) = (a.parse().expect(a), b.parse().expect(b));
            assert_eq!(ranges_conflict(&a, &b), ranges_conflict(&b, &a));
            ranges_conflict(&a, &b)
        };
        for (a, b) in [
            ("^1", "^2"),
            ("<1.0.0", ">=1.0.0"),
            ("=1.2.3", "^1.3"),
            ("~1.2", "^1.3"),
            (">1", "<=1.9"),
            (">1.2.3", "<=1.2.3"),
            ("^0.1", "^0.2"),
        ] {
            assert!(conflict(a, b), "{a} and {b}");
        }
        for (a, b) in [
            ("^1", "^1.0"),
            ("^1", ">=1.0.0, <2.0.0"),
            ("^1", "^1.2"),
            ("<2.0.0", "<1.0.0"),
            (">1.0.0", "<2.0.0"),
            (">1.2.3", "<1.2.5"),
            (">1.2", "<1.4"),
            (">1", "<3"),
            ("*", "^7"),
            ("=1.2.3", "~1.2"),
        ] {
            assert!(!conflict(a, b), "{a} and {b}");
        }
    }

    #[test]
    fn conflict_names_at_most_five_extensions_and_counts_the_others() {
        let mut manifests = vec![
            ext("a", "1.0.0", &[("lib", "^1")]),
            ext("lib", "9.0.0", &[]),
        ];
        for major in 2..=8 {
            let range = format!("^{major}");
            manifests.push(ext(&format!("e{major}"), "1.0.0", &[("lib", &range)]));
        }
        let resolution = resolve_all(&manifests);
        let message = rejected(
            &resolution,
            "a",
            &[
                "conflict with extension `e2`",
                "`e6`",
                "and 2 more extensions",
            ],
        );
        assert!(!message.contains("`e7`"), "{message}");
        assert!(!message.contains("`e8`"), "{message}");
    }

    #[test]
    fn extension_that_is_rejected_for_another_reason_is_not_a_conflict_party() {
        let mut manifests = vec![
            ext("a", "1.0.0", &[("lib", "^1")]),
            // Rejected for the SDK range.
            ext("b", "1.0.0", &[("lib", "^2")]),
            // Rejected for a dependency that is not present.
            ext("c", "1.0.0", &[("absent", "^1"), ("lib", "^3")]),
            // Rejected for the range of another dependency.
            ext("d", "1.0.0", &[("base", "^2"), ("lib", "^4")]),
            ext("e", "1.0.0", &[("lib", "^5")]),
            ext("base", "1.0.0", &[]),
            ext("lib", "9.0.0", &[]),
        ];
        manifests[1].sdk = "^9".parse().expect("valid range");
        let resolution = resolve_all(&manifests);
        let e = "extension `e`, which depends on `lib` `^5`";
        let message = rejected(&resolution, "a", &[&format!("conflict with {e}")]);
        for other in ["`b`", "`c`", "`d`"] {
            assert!(!message.contains(other), "{message}");
        }
        rejected(&resolution, "b", &["SDK"]);
        rejected(&resolution, "c", &["`absent` is not present"]);
        let message = rejected(&resolution, "d", &["`base`"]);
        assert!(!message.contains("conflict"), "{message}");
    }

    #[test]
    fn two_manifests_with_the_same_id_are_rejected() {
        let resolution = resolve_all(&[
            ext("lib", "2.0.0", &[]),
            ext("lib", "1.0.0", &[]),
            ext("a", "1.0.0", &[("lib", "^1")]),
            ext("z", "1.0.0", &[]),
        ]);
        rejected(
            &resolution,
            "lib",
            &["`lib`", "2 manifests", "1.0.0, 2.0.0"],
        );
        rejected(&resolution, "a", &["`a`", "`lib`", "rejected"]);
        assert_eq!(order(&resolution), ["z"]);
    }

    #[test]
    fn cycle_rejects_each_member_and_names_the_cycle() {
        let resolution = resolve_all(&[
            ext("c", "1.0.0", &[("a", "^1")]),
            ext("a", "1.0.0", &[("b", "^1")]),
            ext("b", "1.0.0", &[("c", "^1")]),
            ext("user", "1.0.0", &[("a", "^1")]),
            ext("z", "1.0.0", &[]),
        ]);
        for id in ["a", "b", "c"] {
            rejected(
                &resolution,
                id,
                &[&format!("`{id}` is in"), "`a` -> `b` -> `c` -> `a`"],
            );
        }
        // Not in the cycle, but it depends on it.
        let message = rejected(&resolution, "user", &["`user`", "`a`", "rejected"]);
        assert!(!message.contains("cycle"));
        assert_eq!(order(&resolution), ["z"]);
    }

    #[test]
    fn rejection_cascades_to_dependents() {
        let resolution = resolve_all(&[
            ext("a", "1.0.0", &[("b", "^1")]),
            ext("b", "1.0.0", &[("c", "^1")]),
            ext("c", "1.0.0", &[("gone", "^1")]),
        ]);
        rejected(&resolution, "c", &["`gone`"]);
        rejected(&resolution, "b", &["`b`", "`c`", "rejected"]);
        rejected(&resolution, "a", &["`a`", "`b`", "rejected"]);
        assert!(order(&resolution).is_empty());
    }

    #[test]
    fn one_rejected_extension_does_not_stop_the_others() {
        let mut manifests = vec![
            ext("bad-dep", "1.0.0", &[("gone", "^1")]),
            ext("good", "1.0.0", &[("lib", "^1")]),
            ext("lib", "1.0.0", &[]),
            ext("bad-sdk", "1.0.0", &[]),
        ];
        manifests[3].sdk = "^9".parse().expect("valid range");
        let resolution = resolve_all(&manifests);
        rejected(&resolution, "bad-dep", &[]);
        rejected(&resolution, "bad-sdk", &[]);
        assert_eq!(order(&resolution), ["lib", "good"]);
    }

    fn diamond() -> Vec<Manifest> {
        vec![
            on_command("top", &[("left", "^1"), ("right", "^1")], ""),
            on_command("left", &[("base", "^1")], ""),
            on_command("right", &[("base", "^1")], ""),
            ext("base", "1.0.0", &[]),
        ]
    }

    #[test]
    fn activation_order_has_dependencies_first_and_shutdown_is_the_reverse() {
        let resolution = resolve_all(&diamond());
        assert_eq!(order(&resolution), ["base", "left", "right", "top"]);
        let shutdown: Vec<&str> = resolution
            .shutdown_order()
            .map(ExtensionId::as_str)
            .collect();
        assert_eq!(shutdown, ["top", "right", "left", "base"]);
    }

    #[test]
    fn result_does_not_depend_on_the_input_order() {
        let mut manifests = diamond();
        manifests.extend([
            ext("a", "1.0.0", &[("base", "^2")]),
            ext("dup", "1.0.0", &[]),
            ext("dup", "2.0.0", &[]),
            ext("x", "1.0.0", &[("y", "^1")]),
            ext("y", "1.0.0", &[("x", "^1")]),
        ]);
        let expected = format!("{:?}", resolve_all(&manifests));
        assert!(expected.contains("Resolved") && expected.contains("Rejected"));
        for _ in 0..manifests.len() {
            manifests.rotate_left(1);
            assert_eq!(format!("{:?}", resolve_all(&manifests)), expected);
        }
        manifests.reverse();
        assert_eq!(format!("{:?}", resolve_all(&manifests)), expected);
    }

    #[test]
    fn index_selects_by_extension_point_command_and_connection() {
        let driver = "[[contributes]]\nkind = \"driver\"\nid = \"pg\"\n\
                      [[activation]]\non = \"extension-point\"\n";
        let connection = "[[activation]]\non = \"connection\"\ntype = \"postgres\"\n";
        let index = ActivationIndex::new(&resolve_all(&[
            ext_with("by-point", "1.0.0", &[], "", driver),
            on_command("by-command", &[], ""),
            ext_with("by-connection", "1.0.0", &[], "", connection),
        ]));
        let plan = |trigger| index.plan(trigger, false);

        let point = plan(ActivationTrigger::ExtensionPoint(ExtensionPoint::Driver));
        assert_eq!(activate(&point), ["by-point"]);
        // `by-point` does not contribute to this extension point.
        let other = plan(ActivationTrigger::ExtensionPoint(ExtensionPoint::Exporter));
        assert!(other.activate.is_empty());

        assert_eq!(
            activate(&plan(ActivationTrigger::Command("by-command.run"))),
            ["by-command"]
        );
        assert!(
            plan(ActivationTrigger::Command("postgres"))
                .activate
                .is_empty()
        );

        assert_eq!(
            activate(&plan(ActivationTrigger::Connection("postgres"))),
            ["by-connection"]
        );
        assert!(
            plan(ActivationTrigger::Connection("mysql"))
                .activate
                .is_empty()
        );
    }

    #[test]
    fn plan_lists_dependencies_first_and_one_time() {
        let index = ActivationIndex::new(&resolve_all(&diamond()));
        let plan = index.plan(ActivationTrigger::Command("top.run"), true);
        assert_eq!(activate(&plan), ["base", "left", "right", "top"]);
        assert!(plan.blocked.is_empty());
        // Only the dependencies of the selected extension are listed.
        let plan = index.plan(ActivationTrigger::Command("left.run"), true);
        assert_eq!(activate(&plan), ["base", "left"]);
    }

    #[test]
    fn requires_ui_is_not_selected_in_a_headless_process() {
        let index = ActivationIndex::new(&resolve_all(&[on_command("panel", &[], UI)]));
        let trigger = ActivationTrigger::Command("panel.run");
        let headless = index.plan(trigger, true);
        assert!(headless.activate.is_empty());
        assert!(headless.blocked.is_empty());
        assert_eq!(activate(&index.plan(trigger, false)), ["panel"]);
    }

    #[test]
    fn headless_extension_that_depends_on_requires_ui_is_blocked() {
        let index = ActivationIndex::new(&resolve_all(&[
            on_command("tool", &[("middle", "^1")], ""),
            ext("middle", "1.0.0", &[("panel", "^1")]),
            ext_with("panel", "1.0.0", &[], UI, ""),
        ]));
        let trigger = ActivationTrigger::Command("tool.run");
        let headless = index.plan(trigger, true);
        assert!(headless.activate.is_empty());
        let (id, reason) = headless
            .blocked
            .iter()
            .next()
            .expect("one blocked extension");
        assert_eq!(id.as_str(), "tool");
        assert_eq!(reason.category(), ErrorCategory::Policy);
        for part in ["`tool`", "`panel`", "requires_ui", "headless"] {
            assert!(reason.message().contains(part), "{}", reason.message());
        }
        let with_ui = index.plan(trigger, false);
        assert_eq!(activate(&with_ui), ["panel", "middle", "tool"]);
        assert!(with_ui.blocked.is_empty());
    }

    #[test]
    fn nothing_is_selected_without_a_matching_event() {
        let index = ActivationIndex::new(&resolve_all(&[
            // Contributes to an extension point, but has no activation event.
            ext_with(
                "silent",
                "1.0.0",
                &[],
                "",
                "[[contributes]]\nkind = \"driver\"\nid = \"s\"\n",
            ),
            // Has an activation event, but is rejected.
            on_command("rejected", &[("gone", "^1")], ""),
        ]));
        for trigger in [
            ActivationTrigger::ExtensionPoint(ExtensionPoint::Driver),
            ActivationTrigger::Command("silent.run"),
            ActivationTrigger::Command("rejected.run"),
            ActivationTrigger::Connection("silent"),
        ] {
            let plan = index.plan(trigger, false);
            assert!(plan.activate.is_empty(), "{trigger:?}");
            assert!(plan.blocked.is_empty(), "{trigger:?}");
        }
    }
    /// R-66 (a): the conflict pass does one lookup for each pair of
    /// dependents, not one for each triple.
    #[test]
    fn conflict_pass_does_at_most_one_lookup_for_each_pair_of_dependents() {
        const DEPENDENTS: usize = 60;
        let mut manifests = vec![ext("lib", "9.0.0", &[])];
        for index in 0..DEPENDENTS {
            // Each range excludes the present version.
            let range = format!("^{}", index % 8 + 1);
            manifests.push(ext(&format!("e{index}"), "1.0.0", &[("lib", &range)]));
        }
        CONFLICT_STEPS.set(0);
        let resolution = resolve_all(&manifests);
        let steps = CONFLICT_STEPS.get();
        rejected(&resolution, "e0", &["conflict with", "more extensions"]);
        assert!(
            steps <= DEPENDENTS * (DEPENDENTS + 1),
            "{steps} lookups for {DEPENDENTS} dependents"
        );
    }

    /// R-93 (a): the conflict pass writes at most [`MAX_CONFLICT_PARTIES`]
    /// parties as text for each rejected dependent. It counts the others.
    #[test]
    fn conflict_pass_writes_only_the_named_parties_as_text() {
        const DEPENDENTS: usize = 60;
        let mut manifests = vec![ext("lib", "9.0.0", &[])];
        for index in 0..DEPENDENTS {
            // Each range excludes the present version: 8 groups of ranges.
            let range = format!("^{}", index % 8 + 1);
            manifests.push(ext(&format!("e{index:02}"), "1.0.0", &[("lib", &range)]));
        }
        CONFLICT_TEXTS.set(0);
        let resolution = resolve_all(&manifests);
        let texts = CONFLICT_TEXTS.get();
        assert!(
            texts <= DEPENDENTS * MAX_CONFLICT_PARTIES,
            "{texts} texts for {DEPENDENTS} dependents"
        );
        // The message is the same: the first 5 parties by id, then the number
        // of the others. `e00` has the range `^1`; 52 dependents have another
        // range.
        let message = rejected(&resolution, "e00", &[]);
        assert!(
            message.ends_with(
                "; this is a conflict with extension `e01`, which depends on `lib` `^2` and \
                 extension `e02`, which depends on `lib` `^3` and extension `e03`, which \
                 depends on `lib` `^4` and extension `e04`, which depends on `lib` `^5` and \
                 extension `e05`, which depends on `lib` `^6` and 47 more extensions"
            ),
            "{message}"
        );
    }

    /// R-66 (b): a long range is cut in each message.
    #[test]
    fn long_range_is_cut_in_the_rejection_reason() {
        let long = format!("<1.0.0-{}", "a".repeat(5000));
        let manifests = [
            ext("a", "1.0.0", &[("lib", &long)]),
            ext("b", "1.0.0", &[("lib", "^3")]),
            ext("c", "1.0.0", &[("gone", &long)]),
            ext("lib", "2.0.0", &[]),
        ];
        let limit = 5 * MAX_RANGE_CHARS + 400;
        for id in ["a", "b", "c"] {
            let message = rejected(
                &resolve_all(&manifests),
                id,
                &["`lib`"][..usize::from(id != "c")],
            );
            assert!(message.len() <= limit, "{id}: {} bytes", message.len());
            assert!(!message.contains(&"a".repeat(MAX_RANGE_CHARS + 1)), "{id}");
        }
        rejected(
            &resolve_all(&manifests),
            "b",
            &["conflict with extension `a`", "..."],
        );
        let mut sdk = ext("s", "1.0.0", &[]);
        sdk.sdk = long.replace('<', ">=").parse().expect("valid range");
        let message = rejected(&resolve_all(&[sdk]), "s", &["SDK", "..."]);
        assert!(message.len() <= limit, "{} bytes", message.len());

        assert_eq!(cut("^1"), "^1");
        let exact = "é".repeat(MAX_RANGE_CHARS);
        assert_eq!(cut(&exact), exact);
        assert_eq!(cut(&format!("{exact}é")), format!("{exact}..."));
    }
}
