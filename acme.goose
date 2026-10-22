// The package's entry: ACME (RFC 8555) for a server that gets and renews its
// own certificates through TLS-ALPN-01 (RFC 8737). It does no network I/O: the
// program's io carries each HTTPS request, and its challenges value serves each
// challenge certificate while the CA checks it (docs/architecture.md).
//
//   let failed = acme::run() {
//       let pem, renew_at = acme::certificate(io, challenges, settings);
//       // serve acme::key_of(pem) and acme::chain_of(pem) until renew_at
//   };
//
// The flow is in order.goose, JWS in jws.goose, PEM and certificate dates in
// der.goose, and the cache, which keeps rustls-acme's layout, in cache.goose.
namespace acme;

import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import .jws;
import .der;
import .cache;
import .order;

let LETS_ENCRYPT = "https://acme-v02.api.letsencrypt.org/directory";
let LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

// What certificate gets, and from where. contacts are URIs, such as
// "mailto:ops@example.com", and may be empty. cache is a directory for the
// account key and the certificate, which certificate makes private; "" keeps
// nothing, and every call orders a certificate.
struct Settings {
    directory: const u8[:],
    contacts: const (const u8[:])[:],
    domains: const (const u8[:])[:],
    cache: const u8[:] = "",
}

// Why certificate failed: the CA's problem document, or the package's own
// reason.
struct Error { message: u8[] }

// Runs F, and returns an empty array when it returned, or the error a call
// inside it failed with. The innermost run catches.
fn run<F>() -> Error[] {
    F();
    return [];
}

// Leaves the innermost run with an Error of message. Its parameter is untyped
// so that it is compiled only where a program calls it (goose-tls's
// docs/goose-findings.md).
fn fail(message) {
    return [Error { message: str(message) }] from run;
}

// An HTTP response, as io's exchange gives it: the status, the headers ACME
// reads, and the body.
struct Response {
    status: i64 = 0,
    location: u8[..1024],
    nonce: u8[..256],
    // Retry-After in seconds; 0 when absent.
    retry_after: i64 = 0,
    body: u8[>..],
}

fn reset(r: Response&) {
    r.status = 0;
    r.location.clear();
    r.nonce.clear();
    r.retry_after = 0;
    r.body.clear();
}
