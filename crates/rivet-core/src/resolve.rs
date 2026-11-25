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
use rivet_sdk::manifest::{ActivationEvent, ExtensionId, ExtensionPoint, Manifest, Version};
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
/// 5. A dependency is present in a version outside the range. If the range
///    of a different extension includes that version, the two ranges are in
///    conflict and the reason names both extensions and both ranges. The
///    extension with the satisfied range is not rejected for this.
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
                manifest.sdk
            ))
        } else {
            manifest
                .dependencies
                .iter()
                .find_map(|(dependency, range)| match unique.get(dependency) {
                    None if !outcomes.contains_key(dependency) => Some(format!(
                        "extension `{id}` depends on `{dependency}` `{range}`, but \
                         `{dependency}` is not present"
                    )),
                    Some(found) if !range.matches(&found.version) => {
                        let mut message = format!(
                            "extension `{id}` depends on `{dependency}` `{range}`, but \
                             `{dependency}` {} is present",
                            found.version
                        );
                        let others = unique.values().filter_map(|other| {
                            let other_range = other.dependencies.get(dependency)?;
                            other_range.matches(&found.version).then(|| {
                                format!(
                                    "extension `{}`, which depends on `{dependency}` \
                                     `{other_range}`",
                                    other.id
                                )
                            })
                        });
                        let others: Vec<String> = others.collect();
                        if !others.is_empty() {
                            message +=
                                &format!("; this is a conflict with {}", others.join(" and "));
                        }
                        Some(message)
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
    Resolution { outcomes, resolved }
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
}
