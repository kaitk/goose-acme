// acme.serve's chooser, in one thread: the lane's mail reaches a worker's
// chooser at the next ClientHello. A name gets its certificate, with h2 by
// ALPN; a renewed certificate goes to new connections while an open one keeps
// its own; a client offering acme-tls/1 gets the challenge's certificate
// while it lasts; and a name with no certificate, or none sent, is refused.
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http from "github.com/kaitk/goose-http@v0.5.17";
import http.tls;
import acme from "../../";
import acme.serve;
import check from "../";

fn pass(from: tls::Conn, to: tls::Conn) {
    var buf: u8[4096] = [0; 4096];
    loop {
        let n = tls::drain(from, buf);
        guard n > 0 else { break; }
        tls::feed(to, buf[..n]);
    }
}

// A handshake from a client that trusts ca, offers protocols, and sends host
// in SNI, with the chooser called at the server's HELLO; the connection pair
// stays open when both ends finish.
fn connect(base: tls::Context, chooser: acme::Chooser&, ca: const u8[:], protocols: const u8[:][:], host: const u8[:]) -> tls::Conn, tls::Conn, tls::Context {
    let cctx, ok = tls::client_trusting(ca, protocols);
    assert(ok);
    let c = tls::connect(cctx, host);
    let s = tls::accept(base);
    var cs = tls::handshake(c);
    var ss = tls::WANT_INPUT;
    for round in 10 {
        pass(c, s);
        if ss != 0 {
            ss = tls::handshake(s);
            if ss == tls::HELLO {
                http::tls_hello(chooser, s);
                ss = tls::handshake(s);
            }
        }
        guard ss != tls::FAILED else { break; }
        pass(s, c);
        if cs != 0 { cs = tls::handshake(c); }
        guard cs != tls::FAILED else { break; }
        guard cs != 0 || ss != 0 else { break; }
    }
    print(host, " offering ", protocols[0], ": ", if cs == 0 && ss == 0 { str("connected, ALPN ", tls::alpn(s)) }
          else if ss == 0 { str("the server answered with ALPN ", tls::alpn(s), ", the client refused its certificate") }
          else { str("refused") });
    return c, s, cctx;
}

fn self_signed(name: const u8[:], cert: u8[>..]&, key: u8[>..]&) {
    let failed = tls::run() {
        let k = tls::key_generate(tls::P256);
        cert.append(tls::self_signed(k, [name], 1));
        key.append(tls::key_pem(k));
        tls::free(k);
    };
    check::eq("errors", failed.len, 0);
}

fn close(c: tls::Conn, s: tls::Conn, cctx: tls::Context) {
    tls::free(c);
    tls::free(s);
    tls::free(cctx);
}

fn main() {
    var pcert: u8[>..] = [];
    var pkey: u8[>..] = [];
    self_signed("a.test", pcert, pkey);
    let base, bok = tls::server(pcert, pkey, ["acme-tls/1"]);
    check::that("the base context, choosing", bok && tls::choose_context(base));

    let box, err = http::mail_open(16, 512);
    check::that("the chooser's box", err.code == 0);
    var chooser = acme::Chooser { box: box, .. };
    var seats = acme::Seats { .. };
    seats.list.push(acme::Seat { to: http::address(box, 0) });

    print("before any certificate:");
    let c0, s0, x0 = connect(base, chooser, pcert, ["h2", "http/1.1"], "a.test");
    close(c0, s0, x0);

    var cert1: u8[>..] = [];
    var key1: u8[>..] = [];
    self_signed("a.test", cert1, key1);
    let ctx1, ok1 = tls::server(cert1, key1, ["h2", "http/1.1"]);
    check::that("a certificate's context", ok1);
    acme::broadcast(seats, acme::CERT, ctx1, "a.test");
    tls::free(ctx1);

    print("its certificate:");
    let c1, s1, x1 = connect(base, chooser, cert1, ["h2", "http/1.1"], "a.test");
    check::that("the client got it", tls::peer_certificate(c1) == cert1);
    let c2, s2, x2 = connect(base, chooser, cert1, ["http/1.1"], "A.Test");
    check::that("by any case", tls::peer_certificate(c2) == cert1);
    close(c2, s2, x2);
    let c3, s3, x3 = connect(base, chooser, cert1, ["h2", "http/1.1"], "b.test");
    close(c3, s3, x3);

    print("renewed:");
    var cert2: u8[>..] = [];
    var key2: u8[>..] = [];
    self_signed("a.test", cert2, key2);
    let ctx2, ok2 = tls::server(cert2, key2, ["h2", "http/1.1"]);
    acme::broadcast(seats, acme::CERT, ctx2, "a.test");
    tls::free(ctx2);
    let c4, s4, x4 = connect(base, chooser, cert2, ["h2", "http/1.1"], "a.test");
    check::that("a new connection gets the new one", tls::peer_certificate(c4) == cert2);
    close(c4, s4, x4);
    check::that("the open one goes on with the old", tls::write(c1, "ping") == 4);
    pass(c1, s1);
    var buf: u8[64] = [0; 64];
    let n = tls::read(s1, buf);
    check::that("  and its data flows", n == 4 && buf[..4] == "ping");
    close(c1, s1, x1);

    print("a challenge:");
    var ccert: u8[>..] = [];
    var ckey: u8[>..] = [];
    var digest: u8[32] = [7; 32];
    let failed = tls::run() {
        let k = tls::key_generate(tls::P256);
        ccert.append(tls::challenge_certificate(k, "a.test", digest));
        ckey.append(tls::key_pem(k));
        tls::free(k);
    };
    check::eq("errors", failed.len, 0);
    let started = acme::run() { acme::challenge_start(seats, "a.test", ccert, ckey); };
    check::eq("errors", started.len, 0);
    // A verifying client refuses the challenge's certificate, whose
    // acmeIdentifier extension is critical: the ACME server checks it itself.
    let c5, s5, x5 = connect(base, chooser, ccert, ["acme-tls/1"], "a.test");
    check::that("the validation gets the challenge's context", tls::alpn(s5) == "acme-tls/1");
    close(c5, s5, x5);
    let c6, s6, x6 = connect(base, chooser, cert2, ["h2", "http/1.1"], "a.test");
    check::that("others still get the certificate", tls::peer_certificate(c6) == cert2);
    close(c6, s6, x6);
    acme::challenge_end(seats, "a.test");
    let c7, s7, x7 = connect(base, chooser, pcert, ["acme-tls/1"], "a.test");
    check::that("after the challenge, the base context's placeholder", tls::alpn(s7) == "acme-tls/1" && tls::peer_certificate(c7) == pcert);
    close(c7, s7, x7);

    check::eq("choices", chooser.choices.len, 1);
    http::mail_close(box);
    for ch in chooser.choices {
        if tls::ok(ch.cert) { tls::free(ch.cert); }
        if tls::ok(ch.challenge) { tls::free(ch.challenge); }
    }
    tls::free(base);
}
