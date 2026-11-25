//! Workspace tooling. Run with `cargo xtask <command>`.

mod arch;

use std::process::ExitCode;

use cargo_metadata::{DependencyKind, MetadataCommand};

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
    // Normal, build and dev dependencies are all listed in `dependencies`.
    let edges: Vec<arch::Edge<'_>> = packages
        .iter()
        .flat_map(|p| {
            p.dependencies
                .iter()
                .filter(|d| d.path.is_some() && crates.contains(&d.name.as_str()))
                .map(|d| arch::Edge {
                    from: p.name.as_str(),
                    to: d.name.as_str(),
                    dev: d.kind == DependencyKind::Development,
                })
        })
        .collect();

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
