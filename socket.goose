// The module acme.socket: an io for acme::certificate over goose-http's
// blocking socket and goose-tls's client TLS, for a thread that runs no event
// loop, such as a goose-rest lane. Only a program that imports this module
// needs goose-http, which its root file declares at the reference this file
// names:
//
//   import acme from "github.com/kaitk/goose-acme@<tag>";
//   import http from "github.com/kaitk/goose-http@v0.5.0";
//   import acme.socket;
//
//   let failed = acme::run() {
//       var io = acme::socket(5000);   // ms per wait; acme::socket(ca, 5000) trusts only ca
//       let pem, renew_at = acme::certificate(io, challenges, settings);
//       acme::free(io);
//   };
//
// goose-http's connect takes localhost or an IP address, not yet a name.
namespace acme;

import std;
import os;
import http from "github.com/kaitk/goose-http@v0.5.0";
import tls from "github.com/kaitk/goose-tls@v0.0.4";

// The client context every request's TLS starts from, the open connection,
// and the limit in milliseconds on each wait (-1: none).
struct Socket { ctx: tls::Context, s: http::Socket, ms: i64 = -1 }

// An io whose TLS trusts OpenSSL's store of certificate authorities, as a
// public CA's directory needs. Fails through acme::fail when OpenSSL can't
// make the context.
fn socket(ms) -> Socket {
    let ctx, ok = tls::client(["http/1.1"]);
    guard ok else { fail(str("a TLS client context: ", tls::error_text())); }
    return Socket { ctx: ctx, s: http::Socket { fd: -1 }, ms: ms };
}

// An io whose TLS trusts only the certificates in ca, PEM text: for a test
// CA such as Pebble.
fn socket(ca: const u8[:], ms) -> Socket {
    let ctx, ok = tls::client_trusting(ca, ["http/1.1"]);
    guard ok else { fail(str("a TLS client context: ", tls::error_text())); }
    return Socket { ctx: ctx, s: http::Socket { fd: -1 }, ms: ms };
}

fn free(t: Socket&) {
    hangup(t);
    if tls::ok(t.ctx) { tls::free(t.ctx); }
    t.ctx = tls::Context { .. };
}

fn exchange(t: Socket&, method: const u8[:], url: const u8[:], body: const u8[:], r: Response&) {
    https(t, t.ctx, method, url, body, r);
}

fn wait(t: Socket&, seconds: i64) { sleep_ms(seconds * 1000); }

fn now(t: Socket&) -> i64 { time() as i64 }

fn open(t: Socket&, host: const u8[:], port: i64, why: u8[>..]&) -> bool {
    hangup(t);
    let s, e = http::connect(host, port, t.ms);
    guard e.code == 0 else {
        format(why, e.call, " ");
        if e.code == http::ECONNREFUSED { why.append("ECONNREFUSED"); }
        else if e.code == http::ETIMEDOUT { why.append("ETIMEDOUT"); }
        else if e.code == http::ENOSYS { why.append("ENOSYS (the host must be localhost or an IP address)"); }
        else { format(why, "error ", e.code); }
        return false;
    }
    t.s = s;
    return true;
}

fn send(t: Socket&, bytes: const u8[:]) -> bool {
    t.s.fd >= 0 && http::send_all(t.s, bytes, t.ms).code == 0
}

fn receive(t: Socket&, buf: u8[:]) -> i64 {
    guard t.s.fd >= 0 else { return -1; }
    http::recv(t.s, buf, t.ms)
}

fn hangup(t: Socket&) { http::hangup(t.s); }
