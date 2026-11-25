# ADR-0017: Extension host lifecycle: as built, and proposed changes

- Status: Proposed
- Date: 2026-11-25

## Context

The extension host was merged with PR #109 (`crates/rivet-core/src/host.rs`). It differs from the diagram of ARCHITECTURE.md §4.4 in two points (rows b and c), and it fixes three things that §4.4 leaves open (rows a, d and e). The signature check (#12) does not exist yet.

As built (read in the code on 2026-11-25):

| # | Topic | Behaviour |
| --- | --- | --- |
| a | Runtime contract | One contract: `ExtensionRuntime::load` gives an `ExtensionInstance` with `activate` and `deactivate`. To drop the instance unloads it. There is no `unload` call that can fail. |
| b | Failed activation | The host publishes two changes: start state → `Active`, then `Active` → `Failed`. |
| c | Forget | The host can remove an extension in `Resolved` or `Rejected` and discover it again. These states have no loaded code. |
| d | Concurrency | One host-wide lock. Lifecycle operations run one after the other. |
| e | Same id in two directories | The later discovery directory wins: bundled < user < workspace. |

## Decision

| # | Position | Change needed |
| --- | --- | --- |
| a | Keep. | None. |
| b | Change. The extension was never active, so the `Active` event is false. Add the edges `Resolved → Failed` and `Inactive → Failed` with the label "activation failed" to §4.4. The host publishes one change. A failed restart stays `Failed` and publishes no change. | Diagram in §4.4 and `transition` in `host.rs`. |
| c | Keep. Add the edges `Resolved → [*]` and `Rejected → [*]` with the label "forgotten for new discovery" to §4.4. Without them, a corrected manifest needs a process restart. | Diagram in §4.4 only. |
| d | Keep for now. Timeouts for calls into extensions come with #11. Use finer locks only when a delay is measured. | None. |
| e | Accept only as long as no release exists. With the signature check (#12): a package MAY replace a package with the same id from an earlier directory only if its signature verifies against the key of the publisher of that id (ADR-0019: the project key for a bundled extension, else the key pinned for the publisher), or in developer mode. Otherwise the earlier package stays and the later package is reported with a reason. | Rule in #12; text in §4.4. |
| f | New, not in PR #109: an extension in `Failed` or `Disabled` has no loaded code. An explicit unload removes it. An explicit reload reads its package again and gives `Resolved` or `Rejected`; it is not activated at once. Discovery alone does not replace it. Without this, a failed extension can be replaced only by a process restart. | Edges `Failed → [*]` and `Disabled → [*]` in §4.4; `transition` in `host.rs` (review fix R-23, not on `main` on this date). |

## Consequences

- b: subscribers of `ExtensionStateChanged` can trust that `Active` means the activation succeeded.
- e: today a workspace directory can replace a bundled extension, for example a driver, with unsigned code. This is the same gap as the missing signature check of §7.7. The project MUST NOT ship a release before #12 closes both (to enforce in the release ticket #62; no check exists).
- e: the precedence bundled < user < workspace itself stays. A user can still override a bundled extension with a package from the same publisher.
- e: a package with an invalid manifest never replaces a valid package with the same id from an earlier directory. It is listed as invalid. As built in PR #109 it does replace it; this is a defect.
- b: since PR #121 the code follows this position: `transition` in `host.rs` has `Resolved`, `Inactive` and `Active` → `Failed`. The table "As built" above shows the state of PR #109.
- The diagram in §4.4 is not changed until the maintainer accepts this ADR.
