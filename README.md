# goose-acme

ACME for [Goose](https://github.com/aardappel/goose): a server gets and renews its own
certificates from Let's Encrypt, or any ACME CA, through TLS-ALPN-01 on the port it
already serves, so one binary can face the internet without Caddy or nginx. The package
does no network I/O: the program's values carry each HTTPS request and serve each
challenge certificate, and the module `acme.socket` carries them over
[goose-http](https://github.com/kaitk/goose-http)'s blocking socket. Keys, signatures,
and certificates are [goose-tls](https://github.com/kaitk/goose-tls)'s; SHA-256 is
[goose-hash](https://github.com/kaitk/goose-hash)'s.

Its cache keeps rustls-acme's layout, so a server that moves from rustls-acme keeps its
account and certificates.

How it works is in [architecture](docs/architecture.md), the choices behind it in
[decisions](docs/decisions.md), and the plan in [tasks](tasks/README.md).

## Status

🟢 works · 🟡 partial or next · 🔴 not yet

| | Feature | Notes |
|---|---|---|
| 🟢 | Orders (RFC 8555) | Account, order, authorizations, finalize, and the chain; ES256 JWS; `badNonce` retried; tested against Pebble 2.8.0. |
| 🟢 | TLS-ALPN-01 (RFC 8737) | The challenge certificate from goose-tls, served by the program between `challenge_start` and `challenge_end`. Pebble validates it. |
| 🟢 | Renewal | Two thirds into the certificate's validity, with the cached account. |
| 🟢 | The cache | rustls-acme's file names and formats, read both ways; directory 0700 and files 0600; each file written whole or not at all. |
| 🟢 | Over goose-http's blocking socket | `acme.socket`, for a lane. |
| 🟡 | Let's Encrypt | Its directory is named by a host name, which goose-http's `connect` doesn't resolve yet (task 001). |
| 🔴 | A goose-http server answering challenges | goose-http's `http.tls` doesn't choose a context per connection yet (task 001). |
| 🔴 | HTTP-01, DNS-01, wildcards | Out of scope ([decisions](docs/decisions.md#scope)). |

## Quick start

A program declares the package in its root file at a tag, with goose-tls and
goose-hash, which it needs, and goose-http for `acme.socket`. It builds with OpenSSL's
headers and libraries installed, as goose-tls asks
([development](docs/development.md#toolchain)):

```goose
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.4";
import http from "github.com/kaitk/goose-http@v0.5.0";
import acme from "github.com/kaitk/goose-acme@v0.0.1";
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

The tag `v0.0.1` has everything marked 🟢 in the table above. Until goose-http's
`connect` resolves names, `acme.socket` reaches a directory at `localhost` or an IP
address, such as Pebble's, and not yet Let's Encrypt's (task 001).
`test/live/pebble.goose` is a whole program against Pebble.

## API

All in namespace `acme`; each call's contract is in
[architecture](docs/architecture.md).

| Call | Does |
|---|---|
| `Settings { directory, contacts, domains, cache }` | The CA's directory URL, contact URIs, DNS names, and the cache's directory (`""` for none) |
| `LETS_ENCRYPT`, `LETS_ENCRYPT_STAGING` | Let's Encrypt's directory URLs |
| `certificate(io, challenges, s) -> pem, renew_at` | The cached certificate while it's before its renewal time, or a new one; `renew_at` in seconds since the epoch |
| `cached(s) -> pem, renew_at` | The cached certificate, with no request; empty when there's none |
| `key_of(pem)`, `chain_of(pem)` | The key's PEM, and the chain's, for `tls::server` |
| `validity(pem) -> not_before, not_after, ok` | The first certificate's dates |
| `run() { ... } -> Error[]`, `fail(message)` | Errors: a failing call leaves the innermost `run` with an `Error` |
| `socket(ms)`, `socket(ca, ms)`, `free(io)` | In `acme.socket`: an `io` over goose-http, trusting OpenSSL's store or `ca` |
| `https(t, ctx, method, url, body, r)` | An `exchange` over any transport with four calls of its own |

## Layout

```text
acme.goose      the package's entry: Settings, Response, run, and fail
order.goose     the flow: certificate, cached, and the requests
jws.goose       base64url, the JWK, and signed requests
https.goose     URLs, HTTP/1.1 requests and responses, and https over a transport
der.goose       PEM, and a certificate's dates
cache.goose     rustls-acme's layout, and its modes
socket.goose    the module acme.socket: an io over goose-http's blocking socket
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
| goose-tls | `github.com/kaitk/goose-tls@v0.0.4` | P-256 keys, ES256, the CSR, the challenge certificate, and client TLS |
| goose-hash | `github.com/kaitk/goose-hash@v0.0.4` | SHA-256 |
| goose-http | `github.com/kaitk/goose-http@v0.5.0`, in `socket.goose` and the programs that import it | Its blocking socket, for `acme.socket` |
| Pebble | `v2.8.0`, in `scripts/pebble.sh` | The live test's CA |

## Credits

The package implements RFC 8555 (ACME), RFC 8737 (TLS-ALPN-01), RFC 7515 and RFC 7638
(JWS and the JWK thumbprint) from their text. Its cache follows
[rustls-acme](https://github.com/FlorianUekermann/rustls-acme) 0.15's `DirCache`. Its
live test runs against Let's Encrypt's [Pebble](https://github.com/letsencrypt/pebble).
