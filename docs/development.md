# Development

The package is Goose with a few lines of C, `shim/mode.c`, which `goose build`
compiles. It imports goose-tls, whose C needs OpenSSL 3.0 or later, and goose-hash, whose
C `goose build` compiles too. The tests and the Pebble run have passed on macOS on arm64
(2026-10-22); they haven't run on Linux or Windows yet.

## Toolchain

Use the Goose pin in [README.md](../README.md#pins). The scripts also need:

| Tool | Requirement | Purpose |
|---|---|---|
| C compiler | clang or gcc; on Windows, MSVC or `clang-cl` | `goose build` of the shims and each test |
| OpenSSL | 3.0 or later, with headers: the system's on Linux, Homebrew's `openssl@3` on macOS ([goose-tls's setup](https://github.com/kaitk/goose-tls/blob/main/docs/development.md#openssl)) | goose-tls |
| git | on `PATH` | `goose build` fetches goose-tls, goose-hash, and goose-http at their pins |
| Python | 3, with its standard library | `test/run_tests.py` and `scripts/challenge.py` |
| POSIX shell, curl, shasum or sha256sum | on `PATH`; Git Bash on Windows | `scripts/goose.sh`, `scripts/test.sh`, and `scripts/pebble.sh` |
| Go | one that builds Pebble `v2.8.0`; Go 1.27.2 did (2026-10-22) | `scripts/pebble.sh` only, to build Pebble |

## Set up the Goose compiler

The scripts use the Goose release pinned in `scripts/goose.sh` (`v2026.3`) unless told
otherwise. The first script that needs the compiler downloads the release's archive for
the platform from [the releases page](https://github.com/aardappel/goose/releases),
checks its SHA-256, and unpacks it into `build/goose-v2026.3-<platform>/`. Run
`scripts/goose.sh` to fetch it and print the compiler's path. Linux on arm64 has no
release archive, so there the script builds the release's tag from source.

`GOOSE` names another compiler binary, and `GOOSE_COMMIT` a full 40-hex commit of
`aardappel/goose`, which the scripts clone into `build/goose-<commit>/` and build with
CMake. Use them only for a Goose fix not yet released.

`acme.build` excludes `build/`, because Goose collects a package's symbol table from
every `.goose` file under its root, and the release's `stdlib/` is there.

## Test

`scripts/test.sh` runs every test that needs no CA, and stops at the first step that
fails:

1. `goose check` of `acme.goose`, and of `test/live/pebble.goose`, which checks
   `socket.goose` with goose-http.
2. `test/run_tests.py`: the tests under `test/<area>/`, each built with `goose build`
   at `-O0` and `-O2` and run, its output checked against `test/expected/<name>.out`.

```sh
scripts/test.sh
python3 test/run_tests.py flow             # one area
python3 test/run_tests.py --bless order    # rewrite test/expected/order.out
```

The areas:

- `test/jws/`: base64url, the JWK and its thumbprint, a key authorization's digest, and
  a signed request's protected header with a JWK and with an account URL.
- `test/https/`: `https` URLs, the requests written, and responses read whole and a
  byte at a time, by length, in chunks, to the close, and malformed or cut.
- `test/der/`: certificate dates in UTCTime and GeneralizedTime, from certificates
  made with `openssl req -x509` (`test/data/utc.pem` and `generalized.pem`), and PEM.
- `test/cache/`: the cache's file names against rustls-acme's, and its modes.
- `test/flow/`: the whole flow against a CA the program fakes (`test/fake.goose`):
  issuance for two names, the cache, renewal with the cached account (`order`); refused
  nonces, an invalid challenge, a refused order, an unreachable CA, and a cached file
  that can't be read (`failures`); and a cache rustls-acme wrote, its account key made
  by ring (`rustls`, below).
- `test/compile/`: `// error:` fixtures, programs that must not compile:
  `acme::certificate` outside `acme::run`.

`test/run_tests.py` skips `test/live/`.

### rustls-acme's files

`test/data/rustls-acme-account.der` is an account key from ring 0.17's
`EcdsaKeyPair::generate_pkcs8`, which rustls-acme 0.15 calls for an account.
`test/data/rustls-acme-cert.pem` is another such key as PEM, a blank line, and a
certificate for it from `openssl req -x509`, valid until 2049: the layout rustls-acme
writes. On 2026-10-22, ring 0.17.14's `EcdsaKeyPair::from_pkcs8` also read both keys
the Pebble run cached, so a cache can move back to rustls-acme.

## Pebble

`scripts/pebble.sh` runs `test/live/pebble.goose` against
[Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's test CA, on this
machine, and checks its output against `test/expected/pebble.out`:

```sh
scripts/pebble.sh
scripts/pebble.sh --record    # write test/expected/pebble.out
```

The first run builds Pebble and `pebble-challtestsrv` at the version the script names
(`v2.8.0`) with `go install` into `build/pebble/bin/`. Pebble's own TLS certificate and
its CA, which the program trusts, come from Pebble's module in Go's module cache. The
script starts:

- `pebble-challtestsrv` as Pebble's DNS on `127.0.0.1:8053`, answering every name with
  `127.0.0.1`, with its own challenge servers off;
- `scripts/challenge.py`, which answers TLS-ALPN-01 on `127.0.0.1:5001` with the
  certificate and key the program writes for each name while its challenge is live;
- Pebble on `127.0.0.1:14000`, its certificates lasting 30 seconds, with
  `PEBBLE_VA_NOSLEEP=1` and `PEBBLE_WFE_NONCEREJECT=0`, so the run neither waits nor
  meets a random `badNonce`.

The program gets a certificate for `acme.test` and `www.acme.test`, gets it again from
the cache, waits for its renewal time, about 20 seconds, and renews it with the cached
account. Logs and the cache are in `build/pebble/run/`. The ports must be free.

## Move the pin

Move a pin in its own commit, with `scripts/test.sh` and `scripts/pebble.sh` passing:
the Goose release in `scripts/goose.sh`, goose-tls and goose-hash in every file that
imports them, and goose-http in `socket.goose`, `test/live/pebble.goose`, and the docs.
