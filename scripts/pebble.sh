#!/bin/sh
# Runs the programs in test/live/ against Pebble, Let's Encrypt's test CA, on
# this machine: Pebble on 127.0.0.1:14000, and pebble-challtestsrv as its DNS
# on 127.0.0.1:8053, answering every name with 127.0.0.1. Pebble validates
# TLS-ALPN-01 on 127.0.0.1:5001, and its certificates last 30 seconds, so each
# program renews one; the run takes about a minute and a half.
#
# - test/live/pebble.goose, with scripts/challenge.py answering TLS-ALPN-01
#   on port 5001 from the files the program writes.
# - test/live/serve.goose, a goose-http server on port 5001 that answers
#   its challenges itself (acme.serve), with Pebble started again to require
#   external account binding, with the key below.
#
# Each program's output must be test/expected/<name>.out.
#
# The first run builds Pebble and pebble-challtestsrv at the version below with
# Go into build/pebble/bin/; Pebble's own TLS certificate comes from its module
# in Go's module cache.
#
#   scripts/pebble.sh            run, and compare with test/expected/
#   scripts/pebble.sh --record   run, and write test/expected/
#
# GOOSE or GOOSE_COMMIT names the compiler (scripts/goose.sh).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/goose.sh"
goose=$GOOSE

pebble_version=v2.8.0
work=$root/build/pebble
bin=$work/bin
record=
[ "${1:-}" = --record ] && record=1
eab_kid=kid-1
eab_key=zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W

command -v go >/dev/null || { echo "scripts/pebble.sh needs Go, to build Pebble (https://go.dev/dl/)" >&2; exit 1; }
for tool in pebble pebble-challtestsrv; do
    if [ ! -x "$bin/$tool" ]; then
        echo "building $tool $pebble_version into $bin" >&2
        GOBIN=$bin go install "github.com/letsencrypt/pebble/v2/cmd/$tool@$pebble_version"
    fi
done
src=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@$pebble_version
[ -f "$src/test/certs/pebble.minica.pem" ] ||
    GOFLAGS=-mod=mod go mod download "github.com/letsencrypt/pebble/v2@$pebble_version"
ca=$src/test/certs/pebble.minica.pem

rm -rf "$work/run"
mkdir -p "$work/run/challenges"

pids=
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null || :; done
}
trap cleanup EXIT INT TERM

"$bin/pebble-challtestsrv" -dns01 127.0.0.1:8053 -defaultIPv4 127.0.0.1 -defaultIPv6 "" \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" -management 127.0.0.1:8055 \
    >"$work/run/challtestsrv.log" 2>&1 &
pids="$pids $!"

# Starts Pebble with external account binding required or not ("true" or
# "false"), and waits for its directory.
pebble=
start_pebble() {
    cat >"$work/run/config.json" <<EOF
{
  "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "$src/test/certs/localhost/cert.pem",
    "privateKey": "$src/test/certs/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": $1,
    "externalAccountMACKeys": { "$eab_kid": "$eab_key" },
    "profiles": {
      "default": { "description": "30 seconds", "validityPeriod": 30 }
    }
  }
}
EOF
    PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
        "$bin/pebble" -config "$work/run/config.json" -dnsserver 127.0.0.1:8053 \
        >>"$work/run/pebble.log" 2>&1 &
    pebble=$!
    pids="$pids $pebble"
    for i in $(seq 50); do
        curl -sf --cacert "$ca" https://localhost:14000/dir >/dev/null && return 0
        sleep 0.2
    done
    echo "Pebble didn't start; see $work/run/pebble.log" >&2
    exit 1
}

stop() {
    kill "$1" 2>/dev/null || :
    wait "$1" 2>/dev/null || :
}

# Builds and runs test/live/$1.goose, with the environment that follows, and
# checks or records its output.
run_live() {
    name=$1
    shift
    "$goose" build -o "$work/run/$name" "$root/test/live/$name.goose" >"$work/run/$name.build.log" 2>&1 ||
        { cat "$work/run/$name.build.log" >&2; exit 1; }
    status=0
    env "$@" "$work/run/$name" >"$work/run/$name.out" 2>"$work/run/$name.err" || status=$?
    cat "$work/run/$name.out"
    [ "$status" = 0 ] || { echo "test/live/$name.goose failed ($status); logs in $work/run" >&2; exit 1; }
    if [ -n "$record" ]; then
        cp "$work/run/$name.out" "$root/test/expected/$name.out"
        echo "wrote test/expected/$name.out"
    elif ! diff -u "$root/test/expected/$name.out" "$work/run/$name.out"; then
        echo "test/live/$name.goose's output differs from test/expected/$name.out" >&2
        exit 1
    fi
}

start_pebble false
python3 "$root/scripts/challenge.py" "$work/run/challenges" 5001 >"$work/run/challenge.log" 2>&1 &
challenge=$!
pids="$pids $challenge"
run_live pebble PEBBLE_DIRECTORY=https://localhost:14000/dir PEBBLE_CA="$ca" \
    ACME_CACHE="$work/run/cache" CHALLENGE_DIR="$work/run/challenges"
stop "$challenge"
stop "$pebble"

start_pebble true
mkdir -p "$work/run/serve-cache"
run_live serve PEBBLE_DIRECTORY=https://localhost:14000/dir PEBBLE_CA="$ca" \
    PEBBLE_ROOTS=https://localhost:15000/roots/0 ACME_CACHE="$work/run/serve-cache" \
    EAB_KID="$eab_kid" EAB_KEY="$eab_key"
echo "== pebble: passed"
