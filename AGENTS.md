# Agent rules

This file holds what every session needs. `agents/` holds the rules for particular work:
read the file a task touches before starting it.

## Project context

- What this is, its API, and its pins: `README.md`
- The decisions, each dated with its reason and trade-off: `docs/decisions.md`. A new
  decision goes there. `docs/architecture.md` describes how the package works for its
  users and changes with each decision that changes it
- Toolchain, local setup, tests, and the Pebble run: `docs/development.md`
- Goose compiler and stdlib gaps found here: `docs/goose-findings.md`
- Task tracking: `tasks/` (see `tasks/README.md`)
- The protocols: RFC 8555 (ACME), RFC 8737 (TLS-ALPN-01), RFC 7515 and RFC 7638 (JWS
  and the JWK thumbprint). The cache follows rustls-acme 0.15's `DirCache`.
- Its first user: goose-rest, whose task 049 asked for it, through goose-http.
- The language: the pinned Goose release's `docs/tutorial.md`, `docs/goose_spec.md`,
  `docs/stdlib.md`, and `docs/packages.md` (how a package declares the packages it
  needs). Read the tutorial before writing Goose; check the spec before assuming a
  feature exists.
- Rules for particular work: `agents/goose.md` (writing Goose, and recording what it
  lacks), and `agents/writing.md` (docs, tasks, and prose reviews)

Follow the recorded decisions; if a change contradicts one, update the doc in the same
change or ask first. Record setup facts and environment traps you find (paths, shell
quirks, Pebble versions, ports) in `docs/development.md`, not in agent memory, so the
next agent finds them. Docs and commits name no people: date a decision or a request
(`(2026-10-22)`), and describe the setup without anyone's machine, checkouts, or home
directory. What only one machine needs, such as where its Goose checkout is, goes in
`CLAUDE.local.md`, which git ignores.

## Keep changes small

Agreed 2026-10-20.

- Meet the requirement's intent with the least machinery. Before building around an
  obstacle, ask whether the requirement needs it at all.
- When a fix starts to need a new public API, a change in another repository, or a
  workaround, stop. Say so in a sentence or two, and propose the simpler reading of the
  requirement.
- A feature's cost falls on the programs that use it: no fields in shared structs and no
  code on shared paths for one feature.
- When a design makes other code compensate (a fallback, a rescan, a special case
  elsewhere), change the design rather than add the compensation.
- Add a setting, a check, or a script option only for a failure that isn't visible
  already.

## Working beside other agents

Several agents work in these repositories at once (2026-10-20).

- Work in a worktree of your own, on a branch from `origin/main`:
  `git worktree add ../goose-acme-<topic> -b <topic> origin/main`. Remove it once the
  branch is merged.
- Leave alone a branch, a commit, or an uncommitted change that isn't yours, in any
  checkout. Ask if it's in your way.
- Keep logs, exports, and scratch files in a directory of your own.
- Problems with your own sandbox, such as no network or no SSH, go in your report,
  not in the docs.

## Goose

- Build with the official Goose release that `scripts/goose.sh` pins. Check for a newer
  release at the start of a session and move the pin to it.
- Don't edit a Goose checkout. Work around a compiler or stdlib gap here, record it in
  `docs/goose-findings.md` as `agents/goose.md` says, and report blockers to the
  maintainer.
- The package does no network I/O: sockets are goose-http's, and a gap there is fixed
  in goose-http, not worked around here. Its only C is `shim/mode.c`, until Goose's
  `os` module can set a file's mode ([decisions](docs/decisions.md#the-cache)).

## Code conventions

- Comment only where the code is hard to follow without it, and say only what a reader
  of that code needs: why, a constraint, or a contract the code can't show. Don't restate
  the next line, and don't describe earlier versions or the task that added the code;
  history belongs in git.
- Edit files with the Edit tool, not with `sed` or a Python or PowerShell script. On
  Windows, line endings differ by file type and a shell adds a layer of escaping, and
  scripted edits break on both.
- Tests follow Goose's own convention: a top-level `test/` by area, each test a small
  program whose printed output a golden file in `test/expected/` checks, `// error:`
  fixtures for code that must not compile, and a runner that batches them with
  `goose --multi-test`. The flow is checked against a fake CA in the program, and
  against Pebble with `scripts/pebble.sh`.

## Commits

- One lean sentence in imperative mood, at most 72 characters.
- No body, no `Co-Authored-By` or any other trailers.
- Fetch and rebase before pushing a finished commit to `origin`.
