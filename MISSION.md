# Database Client — Feature List

A fast, headless-first database client for PostgreSQL and MySQL, including the AWS and GCP managed offerings with their native IAM auth. Every feature, built-in or third-party, is an extension from day one.

## Goals & Principles

- **Headless first:** the core engine is a complete product without a UI; the desktop UI is one client on top of it.
- **Pluggable from day one:** built-in features use the same public extension API as third-party extensions. No private hooks.
- **Fast:** Rust end to end, streamed results, no JVM, lazy extension activation.
- **Focused:** PostgreSQL and MySQL first. Other engines come later as driver extensions only.
- **Cloud-native auth:** AWS and GCP IAM authentication is a first-class path, not a workaround.

## Target Platforms & IAM Auth

| Platform | Engines | Native IAM auth |
| --- | --- | --- |
| Self-managed | PostgreSQL, MySQL | none (password, client certificates) |
| AWS RDS | PostgreSQL, MySQL | RDS IAM DB auth: SigV4-signed token (15 min) as password over TLS |
| AWS Aurora | PostgreSQL, MySQL | same as RDS |
| AWS RDS Proxy | PostgreSQL, MySQL | IAM auth at the proxy |
| GCP Cloud SQL | PostgreSQL, MySQL | IAM DB auth: OAuth2 access token as password over TLS, or connector flow with ephemeral client certs |
| GCP AlloyDB | PostgreSQL | IAM DB auth: OAuth2 access token as password, or connector / Auth Proxy flow |

Credential sources: the AWS SDK default chain (profiles, SSO, env, instance and web-identity roles) and GCP Application Default Credentials (gcloud user, service account, workload identity). Role assumption and service-account impersonation can be set per connection profile. Tokens refresh before expiry, and reconnect is transparent.

## Architecture

Layers from bottom to top. Layers 1–3 ship as the headless product. The UI talks to the engine through the same API, either in-process or via the daemon.

1. **Core Engine** — runtime, extension host, core services
2. **Capability Extensions** — drivers, auth, tunnels, metadata, execution, transfer, models
3. **Headless Interfaces** — CLI, daemon, control API, tunnel/proxy, scripting
4. **UI Shell** — the Rust windowing system, a client of the engine
5. **UI Extensions** — editor, grid, navigator, diagrams

## 1. Core Engine & Extension System

- Extension host: load, unload and hot-reload extensions at runtime
- Manifest per extension: id, version, dependencies, contributed extension points, required capabilities, `requires_ui` flag
- Semver dependency resolution; lazy activation on first use
- Runtimes: WASM component model (sandboxed, default) and native plugins via a stable C ABI (for drivers and performance-critical code)
- Public, versioned extension SDK from v1; all built-in features are written against it
- Extension points: drivers, auth providers, credential sources, tunnel/proxy providers, metadata providers, result sinks, importers/exporters, model providers, CLI commands, API endpoints, UI views/commands/panels
- Capability-based permissions (network, filesystem, secrets, clipboard), granted per extension
- Service registry, event bus and command bus as the only coupling between extensions
- Core services: layered settings (default → user → workspace → connection), secret store (OS keychain or external secret manager), structured logging and tracing, job scheduler with progress and cancellation
- Unified data model: connections, catalog metadata, streamed result sets (Apache Arrow)
- Fault isolation: a crashing extension is contained and restartable; resource limits per extension
- Extension registry: signed packages, versioned updates, rollback
- Test harness for extensions, with a mock engine and database fixtures

## 2. Capability Extensions (headless)

### Connectivity & Auth

- PostgreSQL and MySQL drivers as extensions, with native async wire-protocol implementations
- AWS: RDS/Aurora IAM token provider, RDS Proxy, Secrets Manager credentials
- GCP: Cloud SQL and AlloyDB IAM token providers, connector flow (instance discovery, ephemeral certs), Secret Manager credentials
- Private connectivity: SSH tunnels with jump hosts and agent forwarding, SOCKS/HTTP proxies, AWS SSM port forwarding, GCP IAP tunnels
- TLS with CA pinning and client certificates
- Connection profiles: environment tags (dev/stage/prod), read-only and confirm-on-write flags
- Pooling, keep-alive, automatic reconnect, timeouts
- Cloud discovery: list RDS/Aurora, Cloud SQL and AlloyDB instances per account or project and create profiles from them

### Schema Metadata

- Catalog introspection: schemas, tables, views, materialized views, routines, sequences, indexes, constraints, triggers, roles, extensions
- DDL generation and schema diff with migration scripts
- Metadata cache with incremental refresh
- Search across object names and definitions

### Query Execution

- Execute statements and scripts with parameter binding, streaming results and cancellation
- Transaction modes: auto-commit, manual, read-only
- Execution plans (EXPLAIN / EXPLAIN ANALYZE) as structured data
- SQL parsing per dialect (PostgreSQL, MySQL) for completion, validation and statement splitting
- Query history

### Data Transfer

- Export to CSV, JSON, Parquet, Excel, SQL INSERT, Markdown
- Import from CSV, JSON, Parquet with column mapping and type inference
- Table-to-table and database-to-database copy, including PostgreSQL ↔ MySQL type mapping
- Integration with pg\_dump/pg\_restore and mysqldump
- Streaming transfers with progress, resume and cancellation

### Administration

- Sessions and locks, kill session
- Users, roles and grants, including IAM-mapped database users
- Server parameters, storage and index statistics
- Activity and slow-query views (pg\_stat\_statements, performance\_schema)

### Integration with External Models

- Model provider extension point: OpenAI-compatible APIs, Anthropic, Bedrock, Vertex AI, self-hosted endpoints (vLLM, Ollama)
- Data policy per connection: nothing / schema only / schema + sampled rows
- Redaction and masking before anything leaves the client
- Use cases: natural language to SQL, explaining queries and plans, optimisation hints, schema documentation, test data generation
- Prompt and response audit log
- Tool endpoint (e.g. MCP) so external agents can use managed connections under the same policies

### Security & Compliance

- Credentials only in the secret store or a cloud secret manager, never in plain configuration
- Production guards: confirmation for destructive statements, row limits, read-only profiles
- Query audit log (who, where, what, when)
- Column-level masking rules
- Signed extensions and permission review on install

## 3. Headless Interfaces

- CLI: run SQL files and scripts against saved profiles; output JSON, CSV or Arrow; CI-friendly exit codes
- Daemon: long-running engine with connection pools, tunnels and jobs; systemd/launchd service
- Tunnel service: exposes managed connections (SSH, IAM, SSM, IAP) as local ports or Unix sockets for any tool
- Auth proxy: a local PostgreSQL/MySQL wire-protocol endpoint that injects and refreshes IAM tokens, so plain clients connect without IAM support
- Protocol proxy policies: audit logging, read-only enforcement, masking
- Scripting: embedded scripting language plus client libraries for external automation
- Control API: local gRPC or JSON-RPC with token auth to manage tunnels, run queries and jobs
- Scheduled jobs: exports, schema diffs, health checks
- Configuration as code (versionable profiles and policies)
- Distribution: single static binary and container image

## 4. UI Shell — Core Windowing System (Rust)

- Native cross-platform windowing (Windows, macOS, Linux; X11 and Wayland)
- GPU-accelerated rendering (wgpu), text shaping, HiDPI and multi-monitor
- Docking layout: tabs, splits, floating windows, restorable workspaces
- Virtualized grids and trees for millions of rows
- Keymaps, command palette, focus management
- Accessibility through native platform APIs (UIA, NSAccessibility, AT-SPI)
- Theming via design tokens; light/dark; colour accents per environment
- UI thread isolated from the async runtime; the UI never blocks on I/O
- Platform services: clipboard, drag-and-drop, file dialogs, notifications
- Connects to an in-process engine or a running daemon

## 5. UI Extensions

- Connection manager, including IAM profile setup and cloud discovery
- Schema navigator and object detail views
- SQL editor: completion, inspections, formatting, refactoring, snippets
- Result grid and data editor: inline editing with pending-change review, foreign-key navigation, JSON/binary viewers
- Plan visualizer
- Schema diff view and ER diagrams
- Admin dashboards (sessions, locks, activity)
- Import/export wizards
- Model assistant panel

## GitHub Labels

Area labels follow the numbered sections: one label per section, and one per subsection for the Capability Extensions (`capability > <area>`). Each issue gets exactly one ticket type, one or more area labels, and any non-functional labels that apply.

### Area Labels

| Label | Explanation |
| --- | --- |
| `core-engine` | Section 1: extension host, SDK, core services, data model |
| `capability > connectivity-auth` | Drivers, password/TLS/SSH, AWS and GCP IAM, tunnels, pooling, cloud discovery |
| `capability > schema-metadata` | Catalog introspection, DDL generation, schema diff, metadata cache |
| `capability > query-execution` | Statement execution, transactions, plans, SQL parsing, query history |
| `capability > data-transfer` | Import, export, database-to-database copy, dump/restore |
| `capability > administration` | Sessions, locks, users and grants, server statistics |
| `capability > external-models` | Model providers, data policies, redaction, MCP endpoint |
| `capability > security-compliance` | Audit log, masking, production guards, extension signing |
| `headless-interfaces` | Section 3: CLI, daemon, tunnel/auth proxy, control API, scripting |
| `ui-shell` | Section 4: Rust windowing system, rendering, layout, input, theming |
| `ui-extensions` | Section 5: editor, grid, navigator, visualizations and other UI views |

### Non-Functional Labels

| Label | Explanation |
| --- | --- |
| `testing` | Unit, integration or end-to-end tests, fixtures, test infrastructure |
| `security` | Vulnerabilities, hardening, secrets handling, threat-model items |
| `performance` | Latency, throughput, memory, startup time, benchmarks |
| `bugfix` | PR that fixes a defect; links to the `bug` issue it closes |
| `documentation` | User docs, extension SDK docs, ADRs |
| `refactoring` | Internal restructuring with no behaviour change |
| `tech-debt` | Known shortcuts to revisit; not urgent |
| `ci-cd` | Build pipelines, release automation, packaging |
| `dependencies` | Crate and toolchain updates |
| `accessibility` | Screen-reader, keyboard-only and contrast work |
| `observability` | Logging, tracing and metrics for the client itself |
| `breaking-change` | Changes the extension API, CLI, config format or control API incompatibly |

### Ticket Types

| Type | Explanation |
| --- | --- |
| `feature` | Accepted, planned functionality with clear scope and acceptance criteria |
| `bug` | Behaviour that deviates from the spec or from documented expectations |
| `task` | Work with no user-facing behaviour change: setup, chores, spikes, infrastructure |
| `feature request` | Proposed functionality, not yet accepted; promoted to `feature` once approved, or closed |

