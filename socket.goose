// The module acme.socket: an io for acme::certificate over goose-http's
// http.client, which makes each request on its blocking socket with goose-tls's
// client TLS, for a thread that runs no event loop, such as a goose-rest lane.
// Only a program that imports this module needs goose-http, which its root
// file declares at the reference this file names:
//
//   import acme from "github.com/kaitk/goose-acme@<tag>";
//   import http from "github.com/kaitk/goose-http@5a780febed8e129d5bbf4c5278df117905e456ed";
//   import acme.socket;
//
//   let failed = acme::run() {
//       var io = acme::socket(5000);   // ms per wait; acme::socket(ca, 5000) trusts only ca
//       let pem, renew_at = acme::certificate(io, challenges, settings);
//       acme::free(io);
//   };
//
// goose-http's connect resolves a name with the system's resolver, which the
// time limit doesn't bound.
namespace acme;

import std;
import os;
import http from "github.com/kaitk/goose-http@5a780febed8e129d5bbf4c5278df117905e456ed";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import http.client;

// The largest response accepted: a certificate chain is a few kilobytes.
let MAX_RESPONSE = 1 << 20;

// The session every request goes through, which keeps its connection to the
// CA between them.
struct Socket { session: http::Session }

// An io whose TLS trusts OpenSSL's store of certificate authorities, as a
// public CA's directory needs. Fails through acme::fail when OpenSSL can't
// make the context.
fn socket(ms) -> Socket {
    var t = Socket { session: http::session(ms) };
    guard tls::ok(t.session.ctx) else { fail(str("a TLS client context: ", tls::error_text())); }
    t.session.max_body = MAX_RESPONSE;
    return t;
}

// An io whose TLS trusts only the certificates in ca, PEM text: for a test
// CA such as Pebble.
fn socket(ca: const u8[:], ms) -> Socket {
    let session, ok = http::session_trusting(ca, ms);
    guard ok else { fail(str("a TLS client context: ", tls::error_text())); }
    var t = Socket { session: session };
    t.session.max_body = MAX_RESPONSE;
    return t;
}

fn free(t: Socket&) { http::free(t.session); }

// One request, its response into r: the status, Location, Replay-Nonce,
// Retry-After in seconds, and the body. method is untyped so that exchange,
// which can fail, is compiled only where the flow calls it inside acme::run
// (docs/goose-findings.md).
fn exchange(t: Socket&, method, url: const u8[:], body: const u8[:], r: Response&) {
    guard starts_with(url, "https://") else { fail(str("not an https URL: ", url)); }
    let got, e = http::request(t.session, method, url) { req =>
        if method == "POST" { http::body(req, "application/jose+json", body); }
    };
    guard e.code == 0 else {
        var why: u8[>..] = [];
        explain(why, e);
        fail(str(method, " ", url, ": ", why));
    }
    let location, has_location = http::header(got, "Location");
    let nonce, has_nonce = http::header(got, "Replay-Nonce");
    guard location.len <= 1024 && nonce.len <= 256 else { fail(str(method, " ", url, ": a malformed HTTP response")); }
    reset(r);
    r.status = got.status;
    r.location.append(location);
    r.nonce.append(nonce);
    let after, has_after = http::header(got, "Retry-After");
    let seconds, valid = parse_int(after);
    if has_after && valid && seconds > 0 { r.retry_after = seconds; }
    r.body.append(got.body);
}

// Appends what e says went wrong, in words where its code has some.
fn explain(why: u8[>..]&, e: http::Error) {
    if e.call == "tls" {
        format(why, "TLS: ", tls::error_text());
        return;
    }
    if e.call == "response" {
        why.append("a malformed HTTP response");
        return;
    }
    if e.call == "url" {
        why.append("not a URL with a host and a valid port");
        return;
    }
    format(why, e.call, " ");
    if e.code == http::ECONNREFUSED { why.append("ECONNREFUSED"); }
    else if e.code == http::ETIMEDOUT { why.append("ETIMEDOUT"); }
    else if e.code == http::ECONNRESET { why.append("ECONNRESET (the connection closed early)"); }
    else if e.code == http::ENOENT { why.append("ENOENT (no such name)"); }
    else if e.code == http::EAGAIN { why.append("EAGAIN (the name's lookup failed for now)"); }
    else { format(why, "error ", e.code); }
}

fn wait(t: Socket&, seconds: i64) { sleep_ms(seconds * 1000); }

fn now(t: Socket&) -> i64 { time() as i64 }
