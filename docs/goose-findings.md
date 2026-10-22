# Goose findings

Gaps in the Goose compiler and stdlib found here, each with the release or commit it
was found on, and how this repository works around it. Bugs come first, then feature
requests, each part from the least work a fix is expected to take to the most. An
entry is deleted once the pin has its fix (`agents/goose.md`).

## Bugs

- **A typed function that leaves `run` doesn't compile outside a program's call
  path** (v2026.3, `8511ae3`; first recorded in goose-tls's findings). `goose check` of
  a file without `main`, or of a program that imports one, takes every fully typed
  function as a root, and rejects one whose call path reaches `return ... from run`
  with "no enclosing call of run on this compile-time call path". `goose build` of a
  program that never calls such a function rejects it too, with "call to fail requires
  an enclosing call of run", though `goose check` of the same program passes. v0.0.1's
  typed `exchange` in `acme.socket` broke every program that imported the module
  without calling `acme::certificate`. Work-around: each function that can call
  `acme::fail` has a generic parameter, so it is compiled only where it's called, and
  `test/socket/imports.goose` builds a program that calls none of them;
  `scripts/test.sh` doesn't check `test/fake.goose` alone, whose overloads are typed. A
  program's own typed `exchange` that calls `acme::fail` needs the same.

## Feature requests

- **No octal integer literals** (v2026.3, `8511ae3`). `0o700` doesn't parse. The cache
  test writes `7 * 64`.
- **`os` can't set a file's mode** (v2026.3, `8511ae3`). `make_dir` and
  `write_file_atomic` create with the umask's modes, and nothing changes them, so a
  private key's file can't be made private in Goose. Work-around: `shim/mode.c` calls
  `chmod` ([decisions](decisions.md#the-cache)). Proposed: a mode parameter on
  `make_dir`, `write_file`, and `write_file_atomic`, ignored on Windows.
