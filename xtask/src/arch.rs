//! Crate dependency rules (ADR-0010).

use Kind::{Core, EngineApi, Ext, Interface, Sdk, UiExt, UiSdk, UiShell};

/// The xtask is tooling, not part of the architecture.
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
];

fn kind(name: &str) -> Option<Kind> {
    Some(match name {
        "rivet-sdk" => Sdk,
        "rivet-engine-api" => EngineApi,
        "rivet-ui-sdk" => UiSdk,
        "rivet-core" => Core,
        "rivet-cli" | "rivet-daemon" | "rivet-proxy" => Interface,
        "rivet-ui-shell" => UiShell,
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

/// Checks the workspace crate names and the `(from, to)` dependency edges
/// between them. Returns one message per violation; empty means compliant.
pub fn violations(crates: &[&str], edges: &[(&str, &str)]) -> Vec<String> {
    let unknown = crates
        .iter()
        .filter(|name| **name != EXEMPT && kind(name).is_none())
        .map(|name| {
            format!(
                "crate `{name}` matches no crate kind in ARCHITECTURE.md §3.2; \
                 add the kind to §3.2 and to the table in xtask/src/arch.rs"
            )
        });
    let forbidden = edges
        .iter()
        .filter(|(from, to)| {
            *from != EXEMPT
                && match (kind(from), kind(to)) {
                    (Some(from), Some(to)) => !permitted(from, to),
                    // An unknown `from` is already reported above.
                    (None, _) => false,
                    (Some(_), None) => true,
                }
        })
        .map(|(from, to)| format!("{from} -> {to} is not permitted by ARCHITECTURE.md §3.2"));
    unknown.chain(forbidden).collect()
}

#[cfg(test)]
mod tests {
    use super::violations;

    fn edge(from: &str, to: &str) -> Vec<String> {
        violations(&[from, to], &[(from, to)])
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
            ("rivet-cli", "rivet-ext-postgres"),
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
    fn unknown_crate_kind_fails() {
        let found = violations(&["rivet-sdk", "rivet-testkit"], &[]);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("`rivet-testkit` matches no crate kind"));
    }

    #[test]
    fn xtask_is_exempt() {
        let found = violations(&["xtask", "rivet-core"], &[("xtask", "rivet-core")]);
        assert_eq!(found, Vec::<String>::new());
    }
}
