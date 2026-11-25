# ADR-0017: Extension host lifecycle: as built, and proposed changes

- Status: Proposed
- Date: 2026-11-25

## Context

The extension host was merged with PR #109 (`crates/rivet-core/src/host.rs`). It differs from the diagram of ARCHITECTURE.md §4.4 in three points (rows b, c and, since PR #131, f: six transitions in the code that the diagram does not have), and it fixes three things that §4.4 leaves open (rows a, d and e). The signature check exists for install (`package.rs`, `install.rs`, #12). The host does not verify a signature when it loads an extension (ticket #138).

As built (read in the code on 2026-11-25):

| # | Topic | Behaviour |
| --- | --- | --- |
| a | Runtime contract | One contract: `ExtensionRuntime::load` gives an `ExtensionInstance` with `activate` and `deactivate`. To drop the instance unloads it. There is no `unload` call that can fail. |
| b | Failed activation | In PR #109 the host published two changes: start state → `Active`, then `Active` → `Failed`. Since PR #121 it does what the decision below says: one change, directly to `Failed`. |
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
| f | New, not in PR #109: an extension in `Failed` or `Disabled` has no loaded code. An explicit unload removes it. An explicit reload reads its package again and gives `Resolved` or `Rejected`; it is not activated at once. Discovery alone does not replace it. Without this, a failed extension can be replaced only by a process restart. | Edges `Failed → [*]` and `Disabled → [*]` in §4.4; `transition` in `host.rs` (review fix R-23, on `main` since PR #131). |

## Consequences

- b: subscribers of `ExtensionStateChanged` can trust that `Active` means the activation succeeded.
- e: today a workspace directory can replace a bundled extension, for example a driver, with unsigned code. This is the same gap as the missing signature check of §7.7. The project MUST NOT ship a release before #12 closes both (to enforce in the release ticket #62; no check exists).
- e: the precedence bundled < user < workspace itself stays. A user can still override a bundled extension with a package from the same publisher.
- e: a package with an invalid manifest never replaces a valid package with the same id from an earlier directory. It is listed as invalid. As built in PR #109 it did replace it; that defect is fixed since PR #131 (read in the doc of the scan in `host.rs` at commit 9b61096; the test was not run for this note).
- b: since PR #121 the code follows this position: `transition` in `host.rs` has `Resolved`, `Inactive` and `Active` → `Failed`. The table "As built" above shows the state of PR #109.
- f, reload and pending restart (review finding R-74; on `main` since PR #187: an accepted reload stops the pending restart when it unloads the entry, a refused reload stops it in `reload_locked`): a reload request cancels the pending automatic restart of this extension first. If the reload is refused, the extension stays `Failed` with the reason of the refusal, and the host does not restart it by itself. The reason of the refusal is set only on the extension whose reload was refused, and only if its state is `Failed`; it is set also when that extension has no pending restart (on `main` since PR #187): the broken package is what blocks it now, and the earlier reason is in the log. The reason is the message of the refusal error. No other extension gets the reason: a dependent keeps its own. Without this, a restart can load the old manifest with the new files.
- Reload of a broken package (review finding R-72, on `main` since PR #182, the log event since PR #187): if the directory of the current package now holds an invalid package, or a later directory holds an invalid package with this id, the reload returns the reason as a `user` error and changes nothing. In this case it never changes the running extension to a package of an earlier directory: a package that broke must not change silently what runs. A different case: the folder in use was deleted, or it now holds a valid package with another id. Then no package of the later directory claims the id, and the reload goes to the valid package of an earlier directory, as a new start of the host does. The reload MUST write one log event that names the old and the new directory. A third case (review finding R-121, not on `main` on this date): the folder in use is valid, but a new folder of the same directory now has the name of the id, so the folder in use lost (ADR rule: only the folder with the name of the id is read). This is not a broken package. The reload loads the folder that won and writes the same log event. Reason: a new start of the host loads that folder too; reload and start must give the same result. As built on this date, the reload is refused each time. (Second case ruled after the first code of the fix. The log event is a `warn` event with the fields `extension`, `old` and `new`.)
- Same id two times in one directory (review finding R-73, on `main` since PR #182): the folder whose name is equal to the id wins; the other folder is listed as invalid with a reason. If no folder has the name of the id, none of them loads: the id is one entry in the state `Rejected`, and its reason names each folder. The folders are not listed one by one as invalid packages (as built in the fix; the record said "each of them is listed as invalid" before). The installer always uses the id as the folder name (ADR-0023).
- Symbolic links in a discovery directory (review finding R-74): a link is never followed. As built, each link is listed as an invalid package. Decision (on `main` since PR #182): only a link to a directory is listed as invalid, with the reason that links are not read; a link to a file and a link without a target are ignored, like a file.
- The diagram in §4.4 is not changed until the maintainer accepts this ADR.
- A package of a later directory that takes the place of a package with the same id from an earlier directory (row e) gives one `warn` event at each scan, not one time per process (on `main` since PR #187; the event has the fields `extension`, `used` and `ignored`). Reason: no state is needed, and a new case is never missed. A reload scans too, so the event can repeat.
