# goose-acme

ACME for [Goose](https://github.com/aardappel/goose): a server gets and renews its own
certificates from Let's Encrypt, or any ACME CA, through TLS-ALPN-01 on the port it
already serves, so one binary can face the internet without Caddy or nginx. The package
does no network I/O: the program's values carry each HTTPS request and serve each
challenge certificate, and the module `acme.socket` carries them with
[goose-http](https://github.com/kaitk/goose-http)'s HTTP client. Keys, signatures,
and certificates are [goose-tls](https://github.com/kaitk/goose-tls)'s; SHA-256 is
[goose-hash](https://github.com/kaitk/goose-hash)'s.

Its cache keeps rustls-acme's layout, or Go's autocert's, as Thruster keeps it, so a
server that moves from either keeps its account and certificates. The module
`acme.serve` runs it all for a goose-http server: a lane that orders and renews, and a
chooser in each worker that answers the challenges and swaps in each new certificate.

How it works is in [architecture](docs/architecture.md), the choices behind it in
[decisions](docs/decisions.md), and the plan in [tasks](tasks/README.md).

## Status

🟢 works · 🟡 partial or next · 🔴 not yet

| | Feature | Notes |
|---|---|---|
| 🟢 | Orders (RFC 8555) | Account, order, authorizations, finalize, and the chain; ES256 JWS; `badNonce` retried; tested against Pebble 2.8.0. |
| 🟢 | TLS-ALPN-01 (RFC 8737) | The challenge certificate from goose-tls, served by the program between `challenge_start` and `challenge_end`. Pebble validates it. |
| 🟢 | Renewal | Two thirds into the certificate's validity, with the cached account. |
| 🟢 | The cache | rustls-acme's file names and formats, or autocert's (`Settings.autocert`), each read both ways; directory 0700 and files 0600; each file written whole or not at all. |
| 🟢 | External account binding | `Settings.eab_kid` and `eab_key`; Pebble checks it. |
| 🟢 | Over goose-http's HTTP client | `acme.socket`, for a lane. |
| 🟢 | A goose-http server answering challenges | `acme.serve`: a lane mails each worker's chooser the challenges and the certificates, which take effect at the next ClientHello; tested against Pebble, renewing while it serves. Needs goose-http `v0.5.17`. |
| 🟡 | Let's Encrypt | Its staging service reached through `acme.socket`: directory, nonce, account, and an order it refused by policy (2026-10-22). A whole certificate needs a public server answering challenges (task 001). |
| 🔴 | HTTP-01, DNS-01, wildcards | Out of scope ([decisions](docs/decisions.md#scope)). |

## Quick start

A program declares the package in its root file at a tag, with goose-tls and
goose-hash, which it needs, and goose-http for `acme.socket`. It builds with OpenSSL's
headers and libraries installed, as goose-tls asks
([development](docs/development.md#toolchain)):

```goose
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http from "github.com/kaitk/goose-http@v0.5.17";
import acme from "github.com/kaitk/goose-acme@v0.0.5";
import acme.socket;

// What the program's TLS server answers acme-tls/1 with: tls::choose_context
// moves such a connection to a context from the certificate and key.
struct Challenges { names: u8[..512] }
fn acme::challenge_start(c: Challenges&, name: const u8[:], cert: const u8[:], key: const u8[:]) { ... }
fn acme::challenge_end(c: Challenges&, name: const u8[:]) { ... }

fn main() {
    let contacts = ["mailto:ops@example.com"];
    let domains = ["example.com", "www.example.com"];
    let s = acme::Settings { directory: acme::LETS_ENCRYPT, contacts: contacts,
                             domains: domains, cache: "/var/lib/app/acme" };
    var challenges = Challenges { .. };
    let failed = acme::run() {
        var io = acme::socket(10000);                  // each wait at most 10 s
        let pem, renew_at = acme::certificate(io, challenges, s);
        acme::free(io);
        let ctx, ok = tls::server(acme::chain_of(pem), acme::key_of(pem), ["http/1.1"]);
        // serve with ctx until renew_at, then call again
    };
    for e in failed { print("ACME: ", e.message); }
}
```

```sh
goose build server.goose
```

The tag `v0.0.5` has everything marked 🟢 in the table above, and reaches Let's
Encrypt's directory by name. `test/live/pebble.goose` is a whole program against Pebble,
and `test/live/serve.goose` a goose-http server on `acme.serve`
([architecture](docs/architecture.md#a-goose-http-server-acmeserve)).

## API

All in namespace `acme`; each call's contract is in
[architecture](docs/architecture.md).

| Call | Does |
|---|---|
| `Settings { directory, contacts, domains, cache, autocert, eab_kid, eab_key }` | The CA's directory URL, contact URIs, DNS names, the cache's directory (`""` for none) and whether it's in autocert's layout, and the external account binding's key identifier and base64url key |
| `LETS_ENCRYPT`, `LETS_ENCRYPT_STAGING` | Let's Encrypt's directory URLs |
| `certificate(io, challenges, s) -> pem, renew_at` | The cached certificate while it's before its renewal time, or a new one; `renew_at` in seconds since the epoch |
| `cached(s) -> pem, renew_at` | The cached certificate, with no request; empty when there's none |
| `key_of(pem)`, `chain_of(pem)` | The key's PEM, and the chain's, for `tls::server` |
| `validity(pem) -> not_before, not_after, ok` | The first certificate's dates |
| `run() { ... } -> Error[]`, `fail(message)` | Errors: a failing call leaves the innermost `run` with an `Error` |
| `socket(ms)`, `socket(ca, ms)`, `free(io)` | In `acme.socket`: an `io` over goose-http's client, trusting OpenSSL's store or `ca` |
| `Plan`, `plan_certificate(p, names)`, `serve(p) -> Service, error`, `tls_server(service)`, `release(server)`, `stop(service)` | In `acme.serve`: the lane, and each worker's TLS server with its chooser |

## Layout

```text
acme.goose      the package's entry: Settings, Response, run, and fail
order.goose     the flow: certificate, cached, and the requests
jws.goose       base64url, the JWK, and signed requests
der.goose       PEM, and a certificate's dates
cache.goose     rustls-acme's layout, autocert's, and their modes
socket.goose    the module acme.socket: an io over goose-http's http.client
serve.goose     the module acme.serve: the lane, and each worker's chooser
shim/mode.c     chmod, until Goose's os module sets modes
test/           the tests by area, the fake CA, and test/live/, which needs Pebble
scripts/        the Goose pin, the test scripts, and the Pebble run
docs/           architecture, decisions, development setup, Goose findings
tasks/          task tracking (tasks/README.md)
```

## Pins

| What | Pin | Why |
|---|---|---|
| Goose compiler | `aardappel/goose` release `v2026.3` (`8511ae3`), which the scripts fetch ([setup](docs/development.md#set-up-the-goose-compiler)) | An official release builds the same on every platform |
| goose-tls | `github.com/kaitk/goose-tls@v0.0.6` | P-256 keys, ES256, the CSR, the challenge certificate, and client TLS |
| goose-hash | `github.com/kaitk/goose-hash@v0.0.4` | SHA-256 |
| goose-http | `github.com/kaitk/goose-http@v0.5.17`, in `socket.goose`, `serve.goose`, and the programs that import them | Its HTTP client, `http.client`, for `acme.socket`; its TLS server and mail, for `acme.serve` |
| Pebble | `v2.8.0`, in `scripts/pebble.sh` | The live test's CA |

## Credits

The package implements RFC 8555 (ACME), RFC 8737 (TLS-ALPN-01), RFC 7515 and RFC 7638
(JWS and the JWK thumbprint) from their text. Its cache follows
[rustls-acme](https://github.com/FlorianUekermann/rustls-acme) 0.15's `DirCache`, or
[autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert)'s. Its
live test runs against Let's Encrypt's [Pebble](https://github.com/letsencrypt/pebble).

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option. Unless you state otherwise, any
contribution you submit for inclusion, as defined in the Apache-2.0 license, is
licensed the same way, without any additional terms or conditions.
