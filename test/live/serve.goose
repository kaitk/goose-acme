// acme.serve against Pebble: a goose-http server on 127.0.0.1:5001, where
// Pebble validates TLS-ALPN-01, gets a certificate for each of two names from
// its own lane, answering the challenges itself, and serves each with h2 or
// HTTP/1.1 by ALPN; renews them while it serves, without a restart, since
// Pebble's certificates last 30 seconds; keeps them in autocert's layout; and
// binds its account with EAB, which this Pebble requires. scripts/pebble.sh
// runs it, and passes the settings below in the environment.
import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http from "github.com/kaitk/goose-http@v0.5.17";
import http.tls;
import http.client;
import acme from "../../";
import acme.serve;
import check from "../";

let PORT = 5001;

thread_fn worker(cfg: http::Config, service: acme::Service) {
    var server = acme::tls_server(service);
    let e = http::serve_epoll(cfg, false, server) { ev, st, out =>
        if ev.kind == http::REQUEST { http::respond(out, 200, "text/plain", "hello"); }
    };
    acme::release(server);
    http::report(e);
}

thread_fn server(cfg: http::Config, service: acme::Service) {
    http::run(cfg, service, worker);
}

fn setting(name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    if !env(name, v) { abort(str(name, " is not set: run scripts/pebble.sh")); }
    return v;
}

// The certificate the server answers name with, and the protocol it chose,
// for a client that trusts root and offers protocols; empty when refused.
fn leaf(root: const u8[:], name: const u8[:], protocols: const u8[:][:]) -> u8[>..], u8[>..] {
    var cert: u8[>..] = [];
    var alpn: u8[>..] = [];
    let cctx, ok = tls::client_trusting(root, protocols);
    guard ok else { return cert, alpn; }
    var s, e = http::connect("127.0.0.1", PORT, 2000);
    if e.code == 0 {
        let c = tls::connect(cctx, name);
        var buf: u8[16384] = [0; 16384];
        for round in 20 {
            let r = tls::handshake(c);
            loop {
                let n = tls::drain(c, buf);
                guard n > 0 else { break; }
                http::send_all(s, buf[..n], 2000);
            }
            if r == 0 { cert.append(tls::peer_certificate(c)); alpn.append(tls::alpn(c)); break; }
            guard r == tls::WANT_INPUT else { break; }
            let n = http::recv(s, buf, 2000);
            guard n > 0 else { break; }
            tls::feed(c, buf[..n]);
        }
        tls::free(c);
        http::hangup(s);
    }
    tls::free(cctx);
    return cert, alpn;
}

// Waits up to seconds for name's certificate to be one other than old.
fn next_leaf(root: const u8[:], name: const u8[:], old: const u8[:], seconds: i64) -> u8[>..] {
    for i in seconds * 5 {
        let cert, alpn = leaf(root, name, ["http/1.1"]);
        if cert.len > 0 && cert != old { return cert; }
        sleep_ms(200);
    }
    return [];
}

fn count(dir: const u8[:]) -> i64 {
    var names: u8[>..] = [];
    list_dir(dir, names);
    var n = 0;
    each_split(names, '\n') { if it.len > 0 && !ends_with(it, ".tmp") { n++; } };
    return n;
}

fn main() {
    var minica: u8[>..] = [];
    guard read_file(setting("PEBBLE_CA"), minica) else { abort("can't read PEBBLE_CA"); }
    let cache = setting("ACME_CACHE");
    var names: u8[>..] = [];
    if list_dir(cache, names) { each_split(names, '\n') { if it.len > 0 { delete_file(str(cache, "/", it)); } }; }

    var plan = acme::Plan { autocert: true, workers: 2, .. };
    plan.directory.append(setting("PEBBLE_DIRECTORY"));
    plan.ca.append(minica);
    plan.cache.append(cache);
    plan.eab_kid.append(setting("EAB_KID"));
    plan.eab_key.append(setting("EAB_KEY"));
    acme::plan_certificate(plan, ["acme.test"]);
    acme::plan_certificate(plan, ["WWW.acme.test"]);
    let service, err = acme::serve(plan);
    check::text("serve", err, "");
    var cfg = http::Config { address: "127.0.0.1", port: PORT, tls: true, workers: 2, .. };
    thread_spawn(server, cfg, service);

    // Pebble's root, which its chains end in, from its management interface.
    var session, sok = http::session_trusting(minica, 10000);
    let roots, rerr = http::get(session, setting("PEBBLE_ROOTS"));
    check::that("Pebble's root", rerr.code == 0 && roots.status == 200);
    var root: u8[>..] = [];
    root.append(roots.body);
    http::free(session);

    let first = next_leaf(root, "acme.test", "", 60);
    check::that("acme.test's certificate, its challenge answered by the server", first.len > 0);
    let www = next_leaf(root, "www.acme.test", "", 60);
    check::that("www.acme.test's, a certificate of its own", www.len > 0 && www != first);
    let h2cert, h2 = leaf(root, "acme.test", ["h2", "http/1.1"]);
    check::text("ALPN offering h2", h2, "h2");
    let h1cert, h1 = leaf(root, "acme.test", ["http/1.1"]);
    check::text("ALPN offering http/1.1", h1, "http/1.1");
    let other, oalpn = leaf(root, "other.test", ["h2", "http/1.1"]);
    check::that("a name not in the plan, refused", other.len == 0);

    var client, cok = http::session_trusting(root, 10000);
    client.via.append("127.0.0.1");
    let got, gerr = http::get(client, str("https://acme.test:", PORT, "/"));
    check::that("a request over it", gerr.code == 0 && got.status == 200 && got.body == "hello");
    http::free(client);

    check::that("the cache, in autocert's layout", count(cache) == 3 && file_exists(str(cache, "/acme_account+key")) &&
                file_exists(str(cache, "/acme.test")) && file_exists(str(cache, "/www.acme.test")));
    var file: u8[>..] = [];
    read_file(str(cache, "/acme.test"), file);
    check::that("the served certificate is the cached one", starts_with(acme::chain_of(file), first));

    let renewed = next_leaf(root, "acme.test", first, 40);
    check::that("renewed while serving, without a restart", renewed.len > 0);
    exit(0);
}
