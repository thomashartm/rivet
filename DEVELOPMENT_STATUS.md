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
| New tickets, not started | #191 Store permission grants on disk, #192 Uninstall an extension, #204 Memory and CPU limits for a native process, #205 MySQL through a tunnel |

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
| #198 | `feat/15-postgres` / `feat-15-postgres` | Crate `rivet-ext-postgres` on `tokio-postgres` 0.7.18, 32 new packages | Rebase, read, gate. Open work: with a transport, a dropped unfinished result must close the connection and the next `execute` must refuse with `connectivity`. |
| #199 | `feat/15-mysql` / `feat-15-mysql` | Crate `rivet-ext-mysql` on `mysql_async` 0.37.1, 50 new packages | Rebase, read, gate. Open work: block more than one statement in one call (decision 83). Cannot run through a tunnel (accepted, #205). No connect timeout. |

- #198 and #199 both change `crates/rivet-testkit/src/conformance.rs` (different lines): merge one, rebase the other.
- The maintainer accepted the libraries and the new packages on 2026-11-26 (section 5): the merge block on the driver pull requests is lifted.

---

## 4. Reviewer findings

The reviewer is a separate session (`rivet-e0`). Last pass: 15. Findings are R-n.

| Level | Open | Fix state |
|---|---|---|
| blocker | R-17 b | Maintainer accepted the limit (decision 75.1). Open: the architect records it (`ARCHITECTURE.md:219`), then report to the reviewer. |
| major | R-109 rest, R-118 | Fixed in #189, under review |
| major | R-114 | Draft #202 |
| major | R-121, R-122, R-123, R-124 | Draft #197 |
| major | R-127 (reload and automatic restart can run at the same moment: `host.rs` about 1464, 1853) | No fix started. Not verified by the orchestrator, not answered. |
| major | R-128 (late crash report of the old instance hits the new one: `host.rs:1971`) | No fix started. Not verified by the orchestrator, not answered. |
| minor | R-125, R-126 (in #197), R-115, R-116 (in #202), R-117 c, R-129, R-130 (records, for the architect), and the reviewer's older list | Wait (maintainer rule) |

- Not reviewed yet: #189, #190, #194, #195, #196, drafts.
- The reviewer asks to check that ten record lines that say "accepted" / "Decision" each match a maintainer answer: 0017:39 :41, 0018:16, 0020:34 :40, 0021:40, 0023:45 :46 :52 :54. Not checked.

---

## 5. Maintainer decisions and open questions

Decided by the maintainer on 2026-11-26:

| Question | Decision |
|---|---|
| 75 (R-17 b: code that cannot be stopped runs on after an unload) | 75.1: accept the limit, with the second release and the warning |
| 79 (driver base) | 79.1: the libraries `tokio-postgres` and `mysql_async` |
| 80 (new packages) | Both accepted: 32 for PostgreSQL, 50 for MySQL |
| 81 (type mapping) | Small first type set, the rest as text |
| 82 (MySQL through a tunnel) | 82.1: accept the limit now; later ticket #205 |
| 83 (MySQL, more than one statement in one call) | The driver must block it |
| 72 (memory / CPU limits of a native process) | Ticket #204 created |
| 74 (config types) | Open for new fields (not implemented yet) |
| 86.1 | Parameter binding comes later, with a contract change |
| 86.2 | The driver splits a script into statements, later |
| 86.3 | The statement guard uses a keyword list, not a full parser |
| 86.4 | The environment tag is free text |
| 86.5 | Read-only in the database session itself comes later |
| 87.1 | The "Amended by ADR-0024" lines in ADR-0003 / §6.6 are covered by the acceptance of the records |
| 87.2 | "Workspace wins" is the rule; the signature condition stays open with #138 |

The architect must write the decisions 75, 81 to 83, 86 and 87 into the records.

Still open:

- Questions 1 to 59 are only in the session transcript.

---

## 6. Next work

1. Verify R-127 and R-128, answer the reviewer.
2. Gate and merge #197, #202, #200, #201.
3. #27 slice 2: the execution path calls the guard (after #200 and #201).
4. #198: tunnel rule for a dropped result. #199: block more than one statement in one call. Then gate and merge both.
5. Config types open for new fields (decision 74): `non_exhaustive` with a constructor.
6. Architect records as `docs/architecture-decisions-28`: the accepted limit of R-17 b; "on main" notes for #189, #190, #194, #195, #196, later #197; ADR-0025 equal to the driver code (wrong password = `auth`, type name in `ColumnMetadata::source_type`); R-130.
7. Not started: #204, #205, #138 (signature check on load), R-78 a (extensions get the secret service), start-up call of `Installer::recover_all()` (it also stops on a directory read error although its doc says otherwise), test close-out of #7 and #9, #191, #192, #5, #95 parts 2 to 4.

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
