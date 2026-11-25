//! Workspace tooling. Run with `cargo xtask <command>`.

mod arch;

use std::process::ExitCode;

use cargo_metadata::{DependencyKind, MetadataCommand, Package};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["check-arch"] => check_arch(),
        _ => {
            eprintln!("usage: cargo xtask check-arch");
            ExitCode::from(2)
        }
    }
}

fn check_arch() -> ExitCode {
    let metadata = match MetadataCommand::new().no_deps().exec() {
        Ok(metadata) => metadata,
        Err(err) => {
            eprintln!("check-arch: cargo metadata failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    let packages = metadata.workspace_packages();
    let crates: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
    let edges = edges(&packages);

    let violations = arch::violations(&crates, &edges);
    if violations.is_empty() {
        println!(
            "check-arch: ok ({} crates, {} workspace edges)",
            crates.len(),
            edges.len()
        );
        return ExitCode::SUCCESS;
    }
    for violation in &violations {
        eprintln!("check-arch: {violation}");
    }
    ExitCode::FAILURE
}

/// The dependencies between the workspace crates.
///
/// - Normal, build and dev dependencies are all listed in `dependencies`.
///   Only a dev-dependency gives `dev: true` (ADR-0016 rule 2).
/// - A dependency counts by its package name, also when it does not come
///   from a path: a registry or git copy of a workspace crate must not
///   bypass the rules.
fn edges<'a>(packages: &[&'a Package]) -> Vec<arch::Edge<'a>> {
    let is_workspace_crate = |name: &str| packages.iter().any(|p| p.name.as_str() == name);
    packages
        .iter()
        .flat_map(|p| {
            p.dependencies
                .iter()
                .filter(|d| is_workspace_crate(&d.name))
                .map(|d| arch::Edge {
                    from: p.name.as_str(),
                    to: d.name.as_str(),
                    dev: d.kind == DependencyKind::Development,
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One dependency as `cargo metadata` prints it. `kind` and `path` are
    /// JSON values.
    fn dependency(name: &str, kind: &str, path: &str) -> String {
        format!(
            r#"{{"name": "{name}", "source": null, "req": "*", "kind": {kind}, "rename": null,
                "optional": false, "uses_default_features": true, "features": [],
                "target": null, "registry": null, "path": {path}}}"#
        )
    }

    /// The output of `cargo metadata --no-deps` for a workspace.
    fn metadata(packages: &[(&str, &[String])]) -> cargo_metadata::Metadata {
        let id = |name: &str| format!("path+file:///w/{name}#0.1.0");
        let package = |(name, dependencies): &(&str, &[String])| {
            format!(
                r#"{{"name": "{name}", "version": "0.1.0", "id": "{}", "source": null,
                    "dependencies": [{}], "targets": [], "features": {{}},
                    "manifest_path": "/w/{name}/Cargo.toml", "edition": "2024"}}"#,
                id(name),
                dependencies.join(",")
            )
        };
        let members: Vec<String> = packages.iter().map(|(name, _)| id(name)).collect();
        let json = format!(
            r#"{{"packages": [{}], "workspace_members": ["{}"], "resolve": null,
                "target_directory": "/w/target", "version": 1, "workspace_root": "/w"}}"#,
            packages.iter().map(package).collect::<Vec<_>>().join(","),
            members.join("\",\"")
        );
        MetadataCommand::parse(json).unwrap()
    }

    fn found(metadata: &cargo_metadata::Metadata) -> Vec<(&str, &str, bool)> {
        let edges = edges(&metadata.workspace_packages());
        edges.iter().map(|e| (e.from, e.to, e.dev)).collect()
    }

    const PATH: &str = "\"/w/dependency\"";

    #[test]
    fn only_a_dev_dependency_is_a_dev_edge() {
        let dependencies = [
            dependency("rivet-sdk", "null", PATH),
            dependency("rivet-sdk", "\"build\"", PATH),
            dependency("rivet-testkit", "\"dev\"", PATH),
        ];
        let metadata = metadata(&[
            ("rivet-ext-postgres", &dependencies),
            ("rivet-sdk", &[]),
            ("rivet-testkit", &[]),
        ]);
        assert_eq!(
            found(&metadata),
            [
                ("rivet-ext-postgres", "rivet-sdk", false),
                ("rivet-ext-postgres", "rivet-sdk", false),
                ("rivet-ext-postgres", "rivet-testkit", true),
            ]
        );
    }

    #[test]
    fn workspace_crate_counts_also_without_a_path() {
        let dependencies = [
            dependency("rivet-core", "null", "null"),
            dependency("tokio", "null", "null"),
            dependency("tempfile", "\"dev\"", PATH),
        ];
        let metadata = metadata(&[("rivet-ext-postgres", &dependencies), ("rivet-core", &[])]);
        assert_eq!(
            found(&metadata),
            [("rivet-ext-postgres", "rivet-core", false)]
        );
    }

    /// The mapping agrees with the real workspace: `cargo metadata` runs.
    #[test]
    fn real_workspace_has_the_testkit_edges() {
        let metadata = MetadataCommand::new().no_deps().exec().unwrap();
        let found = found(&metadata);
        assert!(found.contains(&("rivet-testkit", "rivet-core", false)));
        assert!(found.contains(&("rivet-testkit", "rivet-sdk", false)));
        // ADR-0016 rule 5: the only edge that the xtask must not have.
        assert!(!found.contains(&("xtask", "rivet-testkit", false)));
    }
}
