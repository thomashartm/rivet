# Development status

Snapshot of 2026-11-26, written at the handover of the orchestrator session. Check `gh pr list` and `gh issue list` before you act on it: GitHub is the source of truth.

Same content on GitHub: Epic #14, comments
[handover note](https://github.com/thomashartm/rivet/issues/14#issuecomment-7186087626),
[correction](https://github.com/thomashartm/rivet/issues/14#issuecomment-7186118677),
[reviewer pass 15](https://github.com/thomashartm/rivet/issues/14#issuecomment-7186160908).

---

## 1. Where the project stands

| Area | State |
|---|---|
| Epic 1 (core engine) | Code is on main. Review fixes continue (section 4). |
| Epic 2 (first drivers, execution, guard) | Started. All of it is in draft pull requests (section 3). |
| Records | ADR-0016 to ADR-0024 are Accepted (#193). ADR-0025 "First database drivers" is Proposed. |
| Open tickets with work | Label `in progress`: #4, #7, #9, #11, #12, #13, #15, #20, #27, #95 |
| New tickets, not started | #191 Store permission grants on disk, #192 Uninstall an extension |

Note: the local `main` checkout in `/Users/thomas/projects/rivet` is far behind `origin/main`. Read code in a worktree or after `git pull`.

---

## 2. Merged in the last session

| PR | Content |
|---|---|
| #187 | Host slice 4 |
| #188 | Records -26 |
| #189 | Installer slice 5: R-109 rest, R-118, R-119 a b c e, FIFO fix for the `review` record |
| #190 | Native tests: R-117 a b, R-105 d |
| #193 | Records -27: maintainer decisions 60 to 71, ADR-0016 to 0024 Accepted, ADR-0025 |
| #194 | Installer test close-out (67 install tests, production code identical) |
| #195 | Driver conformance suite `rivet_testkit::conformance` (`run_all(&dyn Driver, &DatabaseFixture, &Sql)`, 8 cases) |
| #196 | R-87: native child runs in its own process group (`rustix` feature `process`, unix only) |

All had green GitHub checks at merge.

---

## 3. Draft pull requests

Delivered by agents. NOT rebased, NOT read, NOT gated by the orchestrator. The agents' reports are the only evidence.

| PR | Branch / worktree | Content | Before merge |
|---|---|---|---|
| #197 | `fix/review-host-5` / `fix-review-host-5` | R-121, R-122, R-123, R-124 (major), R-125, R-126 | Rebase, read (concurrency), full gate with 30 host loops. Touches the same code as R-127 and R-128. |
| #202 | `fix/review-wasm-5` / `fix-review-wasm-5` | R-114 (major), R-115, R-116 | The agent sent no final report: full gate. |
| #200 | `feat/27-execute` / `feat-27-execute` | #27 slice 1: `rivet_core::execute::execute(...)` runs a statement as a job | Rebase, read, gate. Open decision: a dropped result ends the job as `Cancelled`. |
| #201 | `feat/20-guard` / `feat-20-guard` | #20 slice 1: `rivet_core::guard::decide(...)`, 70 classifier cases | Rebase, read, gate. |
| #198 | `feat/15-postgres` / `feat-15-postgres` | Crate `rivet-ext-postgres` on `tokio-postgres` 0.7.18, 32 new packages | Maintainer answers 79, 80. Open work: with a transport, a dropped unfinished result must close the connection and the next `execute` must refuse with `connectivity`. |
| #199 | `feat/15-mysql` / `feat-15-mysql` | Crate `rivet-ext-mysql` on `mysql_async` 0.37.1, 50 new packages | Maintainer answers 79, 80, 82. Cannot run through a tunnel. Multi-statements on, no connect timeout. |

- #198 and #199 both change `crates/rivet-testkit/src/conformance.rs` (different lines): merge one, rebase the other.
- No driver pull request is merged before the maintainer answers 79, 80 and 82.

---

## 4. Reviewer findings

The reviewer is a separate session (`rivet-e0`). Last pass: 15. Findings are R-n.

| Level | Open | Fix state |
|---|---|---|
| blocker | R-17 b | Waits for maintainer question 75. `ARCHITECTURE.md:219` stays unchanged until then. |
| major | R-109 rest, R-118 | Fixed in #189, under review |
| major | R-114 | Draft #202 |
| major | R-121, R-122, R-123, R-124 | Draft #197 |
| major | R-127 (reload and automatic restart can run at the same moment: `host.rs` about 1464, 1853) | No fix started. Not verified by the orchestrator, not answered. |
| major | R-128 (late crash report of the old instance hits the new one: `host.rs:1971`) | No fix started. Not verified by the orchestrator, not answered. |
| minor | R-125, R-126 (in #197), R-115, R-116 (in #202), R-117 c, R-129, R-130 (records, for the architect), and the reviewer's older list | Wait (maintainer rule) |

- Not reviewed yet: #189, #190, #194, #195, #196, drafts.
- The reviewer asks to check that ten record lines that say "accepted" / "Decision" each match a maintainer answer: 0017:39 :41, 0018:16, 0020:34 :40, 0021:40, 0023:45 :46 :52 :54. Not checked.

---

## 5. Open maintainer questions

- 75. Code that cannot be stopped can run on after an unload (R-17 b).
  - 75.1 Accept the limit, second release plus warning (suggested for now, not decided).
  - 75.2 Only jobs that can be stopped.
  - 75.3 Blocking code only in a killable process (suggested for later, not decided).
- 79. Drivers on `tokio-postgres` / `mysql_async` (79.1, in use) or own protocol code (79.2).
- 80. Accept the new packages (32 PostgreSQL, 50 MySQL).
- 81. Small first type mapping, the rest as text.
- 82. MySQL through a tunnel: accept the limit now with a later ticket (82.1) or own connection code on `mysql_common` now (82.2).
- 83. Must the MySQL driver block more than one statement in one call.
- 72. Ticket for memory / CPU limits of a native process.
- 74. Config types open for new fields.
- From the architect for #27 and #20: parameter binding needs a contract change; who splits a script; keyword list or parser; environment tag as free text; read-only also in the database session.
- Two readings to confirm: the "Amended by ADR-0024" lines in ADR-0003 / §6.6 are covered by the acceptance; "workspace wins" is the rule and the signature condition stays open with #138.
- Questions 1 to 59 are only in the session transcript.

---

## 6. Next work

1. Verify R-127 and R-128, answer the reviewer.
2. Gate and merge #197, #202, #200, #201.
3. #27 slice 2: the execution path calls the guard (after #200 and #201).
4. #198: tunnel rule for a dropped result. #198 and #199 merge after the maintainer answers.
5. Architect records as `docs/architecture-decisions-28`: "on main" notes for #189, #190, #194, #195, #196, later #197; ADR-0025 equal to the driver code (wrong password = `auth`, type name in `ColumnMetadata::source_type`); R-130.
6. Not started: #138 (signature check on load), R-78 a (extensions get the secret service), start-up call of `Installer::recover_all()` (it also stops on a directory read error although its doc says otherwise), test close-out of #7 and #9, #191, #192, #5, #95 parts 2 to 4.

---

## 7. Working rules from the maintainer

- Only blocker and major reviewer findings get fixed now. Minor ones wait. Do not over-polish.
- Epic 2 runs in parallel with review fixes. Four implementation agents active, plus one architect agent.
- Model per task: `haiku` mechanical, `sonnet` ordinary, `opus` hard (concurrency, security, architecture).
- Acceptance criteria go into the ticket before work. Boxes are ticked only after the reviewer's verdict.
- Agents work in git worktrees under `~/worktrees/rivet/`. The orchestrator may commit, push, open and merge pull requests after its own review.
- `ARCHITECTURE.md` and ADRs are changed only by the architect agent.
- No force-push, no history rewrite.

---

## 8. Environment

| Item | State |
|---|---|
| Worktrees `~/worktrees/rivet/` | `architecture` (clean, 7 commits behind main), the six draft worktrees of section 3, `test-closeout-permissions-secrets` (empty), `review` (reviewer) |
| Test databases | `docker/compose.test.yml`, project `rivet-test`, running: PostgreSQL on 127.0.0.1:54329, MySQL. `RIVET_TEST_CONTAINERS=1` turns the container tests on. |
| Gate | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`, `cargo xtask check-arch`, `cargo deny check`; repeat loops only for concurrency changes |
| macOS | No `timeout` command: use `perl -e 'alarm 240; exec @ARGV' ...` |
