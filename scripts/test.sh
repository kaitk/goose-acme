#!/bin/sh
# Runs every test that needs no CA, and fails on the first step that fails:
# the typecheck of acme.goose, and of test/live/pebble.goose, which checks
# socket.goose with goose-http, then the tests under test/<area>/
# (test/run_tests.py, which reports all of its failures), whose builds check
# the helpers in test/. scripts/pebble.sh runs test/live/ against Pebble.
#
# A helper isn't checked alone: goose check of a file without main takes
# each typed function as a root, and the fake's overloads call acme::fail
# outside acme::run there (docs/goose-findings.md).
#
# GOOSE or GOOSE_COMMIT names the compiler (default: the pinned release,
# scripts/goose.sh), and CC the C compiler for goose build (default: the one
# goose build finds).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"
goose=$GOOSE

step() {
    echo
    echo "== $*"
}

for f in "$root"/acme.goose "$root"/test/live/*.goose; do
    step "check ${f#"$root"/}"
    "$goose" check "$f"
done

step "test/run_tests.py"
python3 "$root/test/run_tests.py"
