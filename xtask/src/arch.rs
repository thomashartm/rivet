//! Crate dependency rules (ADR-0010).

use Kind::{Core, EngineApi, Ext, Interface, Sdk, TestKit, UiExt, UiSdk, UiShell};

/// The xtask is tooling, not part of the architecture. One rule applies to it
/// too: it uses the testkit as a dev-dependency only (ADR-0016 rule 2).
const EXEMPT: &str = "xtask";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Sdk,
    EngineApi,
    UiSdk,
    Core,
    Ext,
    /// `rivet-cli`, `rivet-daemon`, `rivet-proxy`.
    Interface,
    UiShell,
    UiExt,
    /// `rivet-testkit`: test support (ADR-0016). Other crates use it as a
    /// dev-dependency only. The crates it depends on do not use it at all.
    TestKit,
}

/// The table in ARCHITECTURE.md §3.2: each crate kind and the kinds it may
/// depend on. This is the only copy; change it together with §3.2. Every pair
/// that is not listed is forbidden.
const PERMITTED: &[(Kind, &[Kind])] = &[
    (Sdk, &[]),
    (EngineApi, &[Sdk]),
    (UiSdk, &[Sdk, EngineApi]),
    (Core, &[Sdk, EngineApi]),
    (Ext, &[Sdk]),
    (Interface, &[Sdk, EngineApi, Core]),
    (UiShell, &[Sdk, EngineApi, UiSdk]),
    (UiExt, &[Sdk, EngineApi, UiSdk]),
    (TestKit, &[Sdk, EngineApi, Core]),
];

fn kind(name: &str) -> Option<Kind> {
    Some(match name {
        "rivet-sdk" => Sdk,
        "rivet-engine-api" => EngineApi,
        "rivet-ui-sdk" => UiSdk,
        "rivet-core" => Core,
        "rivet-cli" | "rivet-daemon" | "rivet-proxy" => Interface,
        "rivet-ui-shell" => UiShell,
        "rivet-testkit" => TestKit,
        _ if name.starts_with("rivet-ui-ext-") => UiExt,
        _ if name.starts_with("rivet-ext-") => Ext,
        _ => return None,
    })
}

fn permitted(from: Kind, to: Kind) -> bool {
    PERMITTED
        .iter()
        .any(|(kind, targets)| *kind == from && targets.contains(&to))
}

/// One dependency between two workspace crates.
#[derive(Clone, Copy, Debug)]
pub struct Edge<'a> {
    pub from: &'a str,
    pub to: &'a str,
    /// `true` for a dev-dependency. `false` for a normal or build dependency.
    pub dev: bool,
}

/// Returns why `edge` is forbidden, or `None` if it is permitted.
fn forbidden(edge: Edge<'_>) -> Option<String> {
    let Edge { from, to, dev } = edge;
    // Test support is in no crate as a normal or build dependency. This is
    // the one rule that looks at the dependency kind.
    let must_be_dev = || format!("{from} -> {to} must be a dev-dependency (ARCHITECTURE.md §3.2)");
    let Some(from_kind) = kind(from) else {
        // The xtask. A crate of an unknown kind is reported in `violations`.
        return (from == EXEMPT && kind(to) == Some(TestKit) && !dev).then(must_be_dev);
    };
    // shortcut: the MVP CLI links the PostgreSQL driver until the extension
    // host can hand out a driver (§3.2 footnote 1); remove this line then.
    if (from, to) == ("rivet-cli", "rivet-ext-postgres") {
        return None;
    }
    let ok = match (from_kind, kind(to)) {
        // No cycle, also not with a dev-dependency: the tests of a crate
        // would see two copies of its types.
        (from, Some(TestKit)) if permitted(TestKit, from) => false,
        (_, Some(TestKit)) if !dev => return Some(must_be_dev()),
        (_, Some(TestKit)) => true,
        (from, Some(to)) => permitted(from, to),
        (_, None) => false,
    };
    (!ok).then(|| format!("{from} -> {to} is not permitted by ARCHITECTURE.md §3.2"))
}

/// Checks the workspace crate names and the dependency edges between them.
/// Returns one message per violation; empty means compliant.
pub fn violations(crates: &[&str], edges: &[Edge<'_>]) -> Vec<String> {
    let unknown = crates
        .iter()
        .filter(|name| **name != EXEMPT && kind(name).is_none())
        .map(|name| {
            format!(
                "crate `{name}` matches no crate kind in ARCHITECTURE.md §3.2; \
                 add the kind to §3.2 and to the table in xtask/src/arch.rs"
            )
        });
    // An unknown `from` gives `None`: it is reported above.
    let forbidden = edges.iter().filter_map(|edge| forbidden(*edge));
    unknown.chain(forbidden).collect()
}

#[cfg(test)]
mod tests {
    use super::{Edge, violations};

    fn check(from: &str, to: &str, dev: bool) -> Vec<String> {
        violations(&[from, to], &[Edge { from, to, dev }])
    }

    /// A normal dependency.
    fn edge(from: &str, to: &str) -> Vec<String> {
        check(from, to, false)
    }

    #[test]
    fn every_yes_in_the_table_passes() {
        let yes = [
            ("rivet-engine-api", "rivet-sdk"),
            ("rivet-ui-sdk", "rivet-sdk"),
            ("rivet-ui-sdk", "rivet-engine-api"),
            ("rivet-core", "rivet-sdk"),
            ("rivet-core", "rivet-engine-api"),
            ("rivet-ext-postgres", "rivet-sdk"),
            ("rivet-cli", "rivet-sdk"),
            ("rivet-daemon", "rivet-engine-api"),
            ("rivet-proxy", "rivet-core"),
            ("rivet-ui-shell", "rivet-sdk"),
            ("rivet-ui-shell", "rivet-engine-api"),
            ("rivet-ui-shell", "rivet-ui-sdk"),
            ("rivet-ui-ext-grid", "rivet-sdk"),
            ("rivet-ui-ext-grid", "rivet-engine-api"),
            ("rivet-ui-ext-grid", "rivet-ui-sdk"),
            ("rivet-testkit", "rivet-sdk"),
            ("rivet-testkit", "rivet-engine-api"),
            ("rivet-testkit", "rivet-core"),
        ];
        for (from, to) in yes {
            assert_eq!(edge(from, to), Vec::<String>::new(), "{from} -> {to}");
        }
    }

    #[test]
    fn bold_no_entries_fail() {
        let bold_no = [
            ("rivet-core", "rivet-ext-postgres"),
            ("rivet-ext-postgres", "rivet-core"),
            ("rivet-ext-postgres", "rivet-ext-aws-iam"),
        ];
        for (from, to) in bold_no {
            assert_eq!(
                edge(from, to),
                [format!(
                    "{from} -> {to} is not permitted by ARCHITECTURE.md §3.2"
                )]
            );
        }
    }

    #[test]
    fn sdk_may_depend_on_nothing() {
        for to in [
            "rivet-engine-api",
            "rivet-ui-sdk",
            "rivet-core",
            "rivet-ext-postgres",
            "rivet-ui-shell",
            "rivet-cli",
            "rivet-ui-ext-grid",
        ] {
            assert_eq!(edge("rivet-sdk", to).len(), 1, "rivet-sdk -> {to}");
        }
    }

    #[test]
    fn footnoted_and_unlisted_edges_fail() {
        for (from, to) in [
            ("rivet-cli", "rivet-ext-mysql"),
            ("rivet-ui-shell", "rivet-core"),
            ("rivet-ui-ext-grid", "rivet-ui-shell"),
            ("rivet-ui-ext-grid", "rivet-ui-ext-tree"),
            ("rivet-core", "rivet-cli"),
            ("rivet-core", "xtask"),
        ] {
            assert_eq!(edge(from, to).len(), 1, "{from} -> {to}");
        }
    }

    #[test]
    fn the_mvp_cli_may_link_the_postgres_driver() {
        assert_eq!(
            edge("rivet-cli", "rivet-ext-postgres"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn testkit_is_a_dev_dependency_only() {
        for from in ["rivet-ext-postgres", "rivet-cli", "rivet-ui-ext-grid"] {
            assert_eq!(check(from, "rivet-testkit", true), Vec::<String>::new());
            assert_eq!(
                edge(from, "rivet-testkit"),
                [format!(
                    "{from} -> rivet-testkit must be a dev-dependency (ARCHITECTURE.md §3.2)"
                )]
            );
        }
    }

    #[test]
    fn crates_that_testkit_depends_on_may_not_use_it_in_any_kind() {
        for from in ["rivet-sdk", "rivet-engine-api", "rivet-core"] {
            for dev in [false, true] {
                assert_eq!(
                    check(from, "rivet-testkit", dev),
                    [format!(
                        "{from} -> rivet-testkit is not permitted by ARCHITECTURE.md §3.2"
                    )]
                );
            }
        }
    }

    #[test]
    fn testkit_may_not_depend_on_extensions_or_ui() {
        for to in ["rivet-ext-postgres", "rivet-ui-sdk", "rivet-cli"] {
            assert_eq!(edge("rivet-testkit", to).len(), 1, "rivet-testkit -> {to}");
        }
    }

    #[test]
    fn dev_dependencies_follow_the_table_too() {
        let found = check("rivet-ext-postgres", "rivet-core", true);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn unknown_crate_kind_fails() {
        let found = violations(&["rivet-sdk", "rivet-unknown"], &[]);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("`rivet-unknown` matches no crate kind"));
    }

    #[test]
    fn xtask_is_exempt() {
        for to in ["rivet-core", "rivet-ext-postgres", "rivet-cli"] {
            for dev in [false, true] {
                assert_eq!(check("xtask", to, dev), Vec::<String>::new(), "{to}");
            }
        }
    }

    /// ADR-0016 rule 2 has no exception for the xtask.
    #[test]
    fn xtask_uses_testkit_as_a_dev_dependency_only() {
        assert_eq!(check("xtask", "rivet-testkit", true), Vec::<String>::new());
        assert_eq!(
            edge("xtask", "rivet-testkit"),
            ["xtask -> rivet-testkit must be a dev-dependency (ARCHITECTURE.md §3.2)"]
        );
    }
}
