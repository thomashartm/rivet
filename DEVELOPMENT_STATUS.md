# Development status

Snapshot of 2026-11-26, written at the handover of the orchestrator session, updated after the merges of 2026-11-26. Check `gh pr list` and `gh issue list` before you act on it: GitHub is the source of truth.

Same content on GitHub: Epic #14, comments
[handover note](https://github.com/thomashartm/rivet/issues/14#issuecomment-7186087626),
[correction](https://github.com/thomashartm/rivet/issues/14#issuecomment-7186118677),
[reviewer pass 15](https://github.com/thomashartm/rivet/issues/14#issuecomment-7186160908).

---

## 1. Where the project stands

| Area | State |
|---|---|
| Epic 1 (core engine) | Code is on main. Review fixes continue (section 4). |
| Epic 2 (first drivers, execution, guard) | Started. #15 drivers, #20 guard slice 1, #27 slice 1 are on main. |
| Records | ADR-0016 to ADR-0024 are Accepted (#193). ADR-0025 "First database drivers" records the MySQL `boolean` exception (#208); still Proposed. |
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
| #197 | Host slice 5: R-121 to R-126. 30 of 30 repeat runs of host/jobs/native tests passed. |
| #198 | PostgreSQL driver. Plus: tunnel connection closes when an unfinished result is dropped; `bytea_output=hex` set at login; 30 s login limit, 10 s cancel limit. |
| #199 | MySQL driver. Plus: a second statement in one call is refused via a prepare step; error 1295 falls back to a normal run. R1: a failed kill closes the connection within 1 s and frees the lock. |
| #200 | #27 slice 1 |
| #201 | #20 slice 1 |
| #202 | WASM slice 5: R-114, R-115, R-116. Plus: the redactor also knows the cleaned form of a secret. |
| #208 | MySQL `tinyint(1)` read as Int8 (maintainer decision 1.1). |

#187 to #196 had green GitHub checks. From #197 on, GitHub Actions did not run (billing block) and was turned off by the maintainer; local gate (fmt, clippy, all tests with containers, check-arch, cargo deny) was the proof.

---

## 3. Draft pull requests

None open.

---

## 4. Reviewer findings

The reviewer is a separate session (`rivet-e0`). Last pass: 15. Findings are R-n.

| Level | Open | Fix state |
|---|---|---|
| blocker | R-17 b | Maintainer accepted the limit (decision 75.1). Open: the architect records it (`ARCHITECTURE.md:219`), then report to the reviewer. |
| major | R-109 rest, R-118 | Fixed in #189, under review |
| major | R-114 | Fixed on main (#202), reviewer verdict pending |
| major | R-121, R-122, R-123, R-124 | Fixed on main (#197), reviewer verdict pending |
| major | R-127 (reload and automatic restart can run at the same moment: `host.rs` about 1464, 1853) | No fix started. Not verified by the orchestrator, not answered. |
| major | R-128 (late crash report of the old instance hits the new one: `host.rs:1971`) | No fix started. Not verified by the orchestrator, not answered. |
| minor | R-125, R-126 (in #197), R-115, R-116 (in #202), R-117 c, R-129, R-130 (records, for the architect), and the reviewer's older list | Wait (maintainer rule) |

- minor (wait), new from the driver reviews: PostgreSQL panic on non-ASCII text from a broken server (`types.rs:72`, `lib.rs:189`); PostgreSQL drop outside a Tokio runtime does not cancel; MySQL VECTOR columns fail; MySQL cancel can race the next statement; MySQL 1295 fallback not checked on MariaDB; MySQL statement that sends no rows runs on after a failed kill (documented limit); 14 surviving mutations in permissions/secrets/logging tests (from the close-out agent, not yet analysed).
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
| R2 of #199 (MySQL tinyint(1)) | 1.1: a number (Int8), recorded in ADR-0025 |
| GitHub Actions | Off (maintainer, 2026-11-26); the maintainer turns it on again |

The architect must write the decisions 75, 81 to 83, 86 and 87 into the records.

Still open:

- Questions 1 to 59 are only in the session transcript.

---

## 6. Next work

1. Verify R-127 and R-128, answer the reviewer.
2. #27 slice 2: the execution path calls the guard.
3. Config types open for new fields (decision 74): `non_exhaustive` with a constructor.
4. Architect records as `docs/architecture-decisions-28`: the accepted limit of R-17 b; "on main" notes for #189, #190, #194, #195, #196, later #197; ADR-0025 equal to the driver code (wrong password = `auth`, type name in `ColumnMetadata::source_type`); R-130.
5. Not started: #204, #205, #138 (signature check on load), R-78 a (extensions get the secret service), start-up call of `Installer::recover_all()` (it also stops on a directory read error although its doc says otherwise), test close-out of #7 and #9, #191, #192, #5, #95 parts 2 to 4.
6. Reviewer: review #197 to #202 and #208.

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
| Merged branches | Worktrees of the merged branches can be removed (not removed yet). |
| `cargo-deny` | 0.22.1 installed locally |
