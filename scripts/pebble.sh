#!/bin/sh
# Runs test/live/pebble.goose against Pebble, Let's Encrypt's test CA, on this
# machine: Pebble on 127.0.0.1:14000, pebble-challtestsrv as its DNS on
# 127.0.0.1:8053, answering every name with 127.0.0.1, and
# scripts/challenge.py answering TLS-ALPN-01 on 127.0.0.1:5001. Pebble's
# certificates last 30 seconds, so the run renews one; it takes about half a
# minute. The program's output must be test/expected/pebble.out.
#
# The first run builds Pebble and pebble-challtestsrv at the version below with
# Go into build/pebble/bin/; Pebble's own TLS certificate comes from its module
# in Go's module cache.
#
#   scripts/pebble.sh            run, and compare with test/expected/pebble.out
#   scripts/pebble.sh --record   run, and write test/expected/pebble.out
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

rm -rf "$work/run"
mkdir -p "$work/run/challenges"
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
    "externalAccountBindingRequired": false,
    "profiles": {
      "default": { "description": "30 seconds", "validityPeriod": 30 }
    }
  }
}
EOF

pids=
cleanup() {
    for p in $pids; do kill "$p" 2>/dev/null || :; done
}
trap cleanup EXIT INT TERM

"$bin/pebble-challtestsrv" -dns01 127.0.0.1:8053 -defaultIPv4 127.0.0.1 -defaultIPv6 "" \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" -management 127.0.0.1:8055 \
    >"$work/run/challtestsrv.log" 2>&1 &
pids="$pids $!"
python3 "$root/scripts/challenge.py" "$work/run/challenges" 5001 >"$work/run/challenge.log" 2>&1 &
pids="$pids $!"
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
    "$bin/pebble" -config "$work/run/config.json" -dnsserver 127.0.0.1:8053 \
    >"$work/run/pebble.log" 2>&1 &
pids="$pids $!"

up=
for i in $(seq 50); do
    if curl -sf --cacert "$src/test/certs/pebble.minica.pem" https://localhost:14000/dir >/dev/null; then
        up=1
        break
    fi
    sleep 0.2
done
[ -n "$up" ] || { echo "Pebble didn't start; see $work/run/pebble.log" >&2; exit 1; }

"$goose" build -o "$work/run/pebble" "$root/test/live/pebble.goose" >"$work/run/build.log" 2>&1 ||
    { cat "$work/run/build.log" >&2; exit 1; }
status=0
PEBBLE_DIRECTORY=https://localhost:14000/dir PEBBLE_CA=$src/test/certs/pebble.minica.pem \
    ACME_CACHE=$work/run/cache CHALLENGE_DIR=$work/run/challenges \
    "$work/run/pebble" >"$work/run/pebble.out" || status=$?
cat "$work/run/pebble.out"
[ "$status" = 0 ] || { echo "test/live/pebble.goose failed ($status); logs in $work/run" >&2; exit 1; }

if [ -n "$record" ]; then
    cp "$work/run/pebble.out" "$root/test/expected/pebble.out"
    echo "wrote test/expected/pebble.out"
elif ! diff -u "$root/test/expected/pebble.out" "$work/run/pebble.out"; then
    echo "test/live/pebble.goose's output differs from test/expected/pebble.out" >&2
    exit 1
fi
echo "== pebble: passed"
