# Architecture Decision Records

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-async-runtime.md) | Async runtime: Tokio | Accepted |
| [0002](0002-wasm-runtime.md) | WASM runtime: Wasmtime | Accepted |
| [0003](0003-native-plugin-placement.md) | Native plugins run out-of-process by default | Accepted |
| [0004](0004-control-api-protocol.md) | Control API: gRPC with Arrow Flight | Accepted |
| [0005](0005-local-persistence.md) | Local persistence: SQLite | Accepted |
| [0006](0006-extension-signing.md) | Extension signing: minisign | Accepted |
| [0007](0007-scripting-adapters.md) | Scripting: adapter framework, Rhai first | Accepted |
| [0008](0008-manifest-and-secret-uris.md) | Manifest name and secret URI scheme | Accepted |
| [0009](0009-crate-layout.md) | Crate layout | Accepted |
| [0010](0010-architecture-check.md) | Architecture check with xtask | Accepted |
| [0011](0011-control-api-token-scopes.md) | Control API token scopes | Accepted |
| [0012](0012-project-licence-open.md) | Project licence is not decided; dependencies stay permissive | Accepted |
| [0013](0013-sdk-bindings-delivery.md) | WIT and C ABI bindings are delivered with the runtimes | Accepted |
| [0014](0014-keychain-optional-on-linux.md) | The OS keychain backend is optional on Linux | Accepted |
| [0015](0015-integration-test-databases.md) | Integration tests use local database containers | Accepted |
| [0016](0016-testkit-dependency-rule.md) | Dependency rule for `rivet-testkit` | Proposed |
| [0017](0017-extension-host-lifecycle.md) | Extension host lifecycle: as built, and proposed changes | Proposed |
| [0018](0018-wasm-runtime-parameters.md) | WASM runtime parameters | Proposed |
| [0019](0019-publisher-identity-and-trust-store.md) | Publisher identity and trust store | Proposed |
| [0020](0020-permission-matching-rules.md) | Permission matching rules | Proposed |
| [0021](0021-extension-supervision.md) | Extension supervision: restart, timeouts and job limit | Proposed |
| [0022](0022-short-secrets-not-redacted.md) | Secrets shorter than 4 bytes are not redacted in logs | Proposed |
| [0023](0023-package-format-and-install-layout.md) | Package format and install layout | Proposed |
| [0024](0024-native-process-runtime.md) | Native process runtime: protocol and supervision | Proposed |

New ADRs use the next free number and the sections Context, Decision, Consequences, Status.

Status values: `Accepted` = decided by the maintainer. `Proposed` = position of the architect, not confirmed by the maintainer.
