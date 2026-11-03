// The module acme.serve: a goose-http server that gets and renews its own
// certificates. A lane thread runs acme::certificate over acme.socket for each
// certificate the plan names, and mails each worker every context it makes:
// each certificate as it's issued or renewed, and each TLS-ALPN-01 challenge
// while the CA checks it. Each worker's chooser takes that mail at the next
// ClientHello, so new connections get a renewed certificate while open ones
// keep theirs, and the challenge is answered on the port the server already
// serves. Only a program that imports this module needs goose-http, which its
// root file declares at the reference this file names:
//
//   import acme from "github.com/kaitk/goose-acme@<tag>";
//   import http from "github.com/kaitk/goose-http@v0.5.17";
//   import tls from "github.com/kaitk/goose-tls@v0.0.6";
//   import http.tls;
//   import acme.serve;
//
//   thread_fn worker(cfg: http::Config, service: acme::Service) {
//       var server = acme::tls_server(service);
//       http::exit_on_error(http::serve_epoll(cfg, fresh, server) { ev, st, out => ... });
//       acme::release(server);
//   }
//
//   var plan = acme::Plan { workers: 4, .. };
//   plan.directory.append(acme::LETS_ENCRYPT);
//   plan.cache.append("/var/lib/app/acme");
//   acme::plan_certificate(plan, ["example.com", "www.example.com"]);
//   let service, err = acme::serve(plan);
//   var cfg = http::Config { port: 443, tls: true, workers: 4, .. };
//   http::run(cfg, service, worker);
//
// A connection whose SNI name has no certificate yet, or none at all, is
// refused: its context offers only acme-tls/1, so a client that offers h2 or
// http/1.1 gets no_application_protocol, as Go's autocert refuses a name it
// has no certificate for.
namespace acme;

import std;
import http from "github.com/kaitk/goose-http@v0.5.17";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import http.tls;
import .socket;

let ACME_TLS = "acme-tls/1";

// What serve's lane gets, and from where: the settings of acme::Settings, as
// flat text, since the plan crosses to the lane's thread. contacts and ca may
// be empty: ca, PEM, is what the directory's certificate chains to, for a
// test CA; without it the lane trusts OpenSSL's store. certificates holds a
// line for each certificate, its names separated by spaces (plan_certificate);
// protocols the ALPN names each certificate's context offers, separated by
// commas, "h2,http/1.1" when empty. The lane waits for workers to join, or 5
// seconds, before its first order, so that each can answer its challenges.
struct Plan {
    directory: u8[..1024],
    contacts: u8[..1024],
    certificates: u8[..4096],
    cache: u8[..1024],
    autocert: bool = false,
    eab_kid: u8[..256],
    eab_key: u8[..256],
    ca: u8[..16384],
    protocols: u8[..128],
    workers: i64 = 0,
}

// What each worker gets: the context its connections are accepted from, and
// the lane's address. Flat, for http::run.
struct Service {
    base: tls::Context,
    lane: http::MailAddress,
    box: http::Box,
    thread: i64 = 0,
}

// Adds a certificate for names, lowercased, to p.
fn plan_certificate(p: Plan&, names: const u8[:][:]) {
    for name, i in names {
        if i > 0 { p.certificates.push(' '); }
        for c in name { p.certificates.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
    }
    p.certificates.push('\n');
}

// Starts the lane for p, and makes the context every connection is accepted
// from, which tls_server's chooser moves to a certificate's. Returns the
// service, or why it can't start.
fn serve(p: Plan) -> Service, u8[>..] {
    var first: u8[>..] = [];
    var names = 0;
    var long = false;
    each_split(p.certificates, '\n') { line =>
        each_split(line, ' ') {
            if it.len > 0 { names++; long = long || it.len > 253; }
            if first.len == 0 && it.len > 0 { first.append(it); }
        };
    };
    guard names > 0 else { return Service { .. }, str("no certificates in the plan"); }
    guard names <= MOST_NAMES && !long else { return Service { .. }, str("a plan names at most ", MOST_NAMES, " names of up to 253 bytes"); }
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var only: (const u8[:])[>..] = [];
    only.push(first);
    let failed = tls::run() {
        let k = tls::key_generate(tls::P256);
        cert.append(tls::self_signed(k, only, 1));
        key.append(tls::key_pem(k));
        tls::free(k);
    };
    for e in failed { return Service { .. }, str("a placeholder certificate: ", e.message); }
    let base, ok = tls::server(cert, key, [ACME_TLS]);
    guard ok && tls::choose_context(base) else { return Service { .. }, str("a server context: ", tls::error_text()); }
    let box, err = http::mail_open(LANE_SLOTS, GRANT_SIZE);
    guard err.code == 0 else { tls::free(base); return Service { .. }, str("the lane's mailbox: error ", err.code); }
    var service = Service { base: base, lane: http::address(box, 0), box: box };
    service.thread = thread_spawn(renewer, box, p);
    return service, [];
}

// Stops the lane, once the workers have returned, and frees the context.
fn stop(service: Service) {
    http::mail_stop(service.box);
    thread_wait(service.thread);
    tls::free(service.base);
}

// The worker's side: a chooser with a mailbox of its own, which joins the
// lane, for http::tls_server.

struct Choice {
    name: u8[..256],
    cert: tls::Context,
    challenge: tls::Context,
}

// Fixed-size, as http::TlsServerOf holds it: a plan names at most MOST_NAMES.
struct Chooser {
    box: http::Box,
    choices: Choice[..32],
}

let MOST_NAMES = 32;

// What the lane mails a worker: a context for a name.
struct Grant {
    ctx: tls::Context,
    name: u8[..256],
}

struct Seat { to: http::MailAddress }

let JOIN: i32 = 1;
let CERT: i32 = 2;
let CHALLENGE: i32 = 3;
let CHALLENGE_END: i32 = 4;
let LANE_SLOTS: i32 = 256;
let CHOOSER_SLOTS: i32 = 128;
let GRANT_SIZE: i32 = 512;

// The worker's TLS server, whose chooser joins the lane: call it in the
// worker's thread, before its loop.
fn tls_server(service: Service) -> http::TlsServerOf<Chooser> {
    let box, err = http::mail_open(CHOOSER_SLOTS, GRANT_SIZE);
    http::exit_on_error(err);
    let seat = Seat { to: http::address(box, 0) };
    var sent = http::mail_send_value(service.lane, JOIN, seat);
    while sent == http::FULL {
        sleep_ms(1);
        sent = http::mail_send_value(service.lane, JOIN, seat);
    }
    if sent == http::TOO_LONG { abort("acme: a seat doesn't fit the lane's mailbox"); }
    return http::tls_server(service.base, Chooser { box: box, .. });
}

// Frees the server, its chooser's contexts, and its mailbox, once its loop has
// returned.
fn release(server: http::TlsServerOf<Chooser>&) {
    http::mail_close(server.chooser.box);
    for ch in server.chooser.choices {
        if tls::ok(ch.cert) { tls::free(ch.cert); }
        if tls::ok(ch.challenge) { tls::free(ch.challenge); }
    }
    server.chooser.choices.clear();
    http::release(server);
}

fn http::tls_hello(c: acme::Chooser&, conn: tls::Conn) {
    if http::mail_pending(c.box) { acme::take(c); }
    let sni = tls::server_name(conn);
    var name: u8[..256] = [];
    acme::host_name(sni, name);
    for &ch in c.choices {
        if ch.name == name {
            if tls::offers(conn, acme::ACME_TLS) {
                if tls::ok(ch.challenge) { tls::use_context(conn, ch.challenge); }
            } else if tls::ok(ch.cert) {
                tls::use_context(conn, ch.cert);
            }
            return;
        }
    }
}

// SNI's name as the plan has it: lowercased, without a final dot. Empty for
// one longer than a DNS name.
fn host_name(sni: const u8[:], out: u8[..256]&) {
    var n = sni.len;
    if n > 0 && sni[n - 1] == '.' { n--; }
    guard n <= 253 else { return; }
    for c in sni[..n] { out.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
}

// Takes the lane's mail: each grant replaces the context the chooser held
// for its name, which open connections keep until they close.
fn take(c: Chooser&) {
    http::mail_take(c.box) { key, tag, bytes =>
        var g = Grant { .. };
        if http::mail_value(bytes, g) { grant(c, tag, g); }
    };
}

fn grant(c: Chooser&, tag: i32, g: Grant) {
    var at = -1;
    for &ch, i in c.choices { if ch.name == g.name { at = i; } }
    if at < 0 {
        if c.choices.len == MOST_NAMES {
            if tls::ok(g.ctx) { tls::free(g.ctx); }
            return;
        }
        c.choices.push(Choice { name: g.name, .. });
        at = c.choices.len - 1;
    }
    let ch .= c.choices[at];
    if tag == CERT {
        if tls::ok(ch.cert) { tls::free(ch.cert); }
        ch.cert = g.ctx;
    } else {
        if tls::ok(ch.challenge) { tls::free(ch.challenge); }
        ch.challenge = if tag == CHALLENGE { g.ctx } else { tls::Context { .. } };
    }
}

// The lane's side.

// A certificate the lane keeps: its names, the context it serves, when to
// try for a new one, and how many tries in a row have failed.
struct Held {
    names: u8[..1024],
    ctx: tls::Context,
    next: i64 = 0,
    failures: i64 = 0,
}

// The workers that joined, as acme::certificate's challenges value.
struct Seats { list: Seat[>..] }

thread_fn renewer(box: http::Box, p: Plan) {
    var seats = Seats { .. };
    var held: Held[>..] = [];
    each_split(p.certificates, '\n') { line => if line.len > 0 { var h = Held { .. }; h.names.append(line); held.push(h); } };
    let now0 = time() as i64;
    for &h in held { load(p, h, now0); }
    let start = time() as i64;
    while seats.list.len < p.workers && (time() as i64) - start < 5 && !http::mail_stopped(box) {
        http::mail_wait(box, 100);
        joins(box, seats, held);
    }
    while !http::mail_stopped(box) {
        joins(box, seats, held);
        prune(seats);
        for &h in held {
            if time() as i64 >= h.next { obtain(p, h, seats); }
        }
        var wake = time() as i64 + 3600;
        for h in held { wake = min(wake, h.next); }
        let ms = max(wake - (time() as i64), 1) * 1000;
        http::mail_wait(box, min(ms, 3600000) as i32);
    }
    for h in held { if tls::ok(h.ctx) { tls::free(h.ctx); } }
    http::mail_close(box);
}

// Takes the workers that joined, and sends each every certificate held.
fn joins(box: http::Box, seats: Seats&, held: Held[:]) {
    http::mail_take(box) { key, tag, bytes =>
        var seat = Seat { .. };
        if tag == JOIN && http::mail_value(bytes, seat) {
            seats.list.push(seat);
            for h in held {
                if tls::ok(h.ctx) { each_split(h.names, ' ') { send(seats, seats.list.len - 1, CERT, h.ctx, it); }; }
            }
        }
    };
}

// Mails seat i a reference of its own to ctx for name: false when its box
// is full or closed, and the reference freed.
fn send(seats: const Seats&, i: i64, tag: i32, ctx: tls::Context, name: const u8[:]) -> bool {
    guard name.len <= 253 else { return false; }
    var g = Grant { ctx: if tls::ok(ctx) { tls::share(ctx) } else { ctx }, .. };
    g.name.append(name);
    let r = http::mail_send_value(seats.list[i].to, tag, g);
    guard r != http::SENT else { return true; }
    if tls::ok(g.ctx) { tls::free(g.ctx); }
    return false;
}

// Mails every seat.
fn broadcast(seats: const Seats&, tag: i32, ctx: tls::Context, name: const u8[:]) {
    for i in seats.list.len { send(seats, i, tag, ctx, name); }
}

// Forgets the seats whose box has closed, as a worker's does once its loop
// has returned.
fn prune(seats: Seats&) {
    var i = 0;
    while i < seats.list.len {
        if http::mail_live(seats.list[i].to) { i++; continue; }
        seats.list[i] = seats.list[seats.list.len - 1];
        seats.list.pop();
    }
}

fn settings_of(p: const Plan&, names: const u8[:], contacts: (const u8[:])[>..]&, domains: (const u8[:])[>..]&) -> Settings {
    each_split(p.contacts, '\n') { if it.len > 0 { contacts.push(it); } };
    each_split(names, ' ') { if it.len > 0 { domains.push(it); } };
    return Settings { directory: p.directory, contacts: contacts, domains: domains, cache: p.cache,
                      autocert: p.autocert, eab_kid: p.eab_kid, eab_key: p.eab_key };
}

// Serves h's cached certificate while it's valid, and tries for a new one
// from its renewal time, or now without one.
fn load(p: const Plan&, h: Held&, now: i64) {
    var contacts: (const u8[:])[>..] = [];
    var domains: (const u8[:])[>..] = [];
    let s = settings_of(p, h.names, contacts, domains);
    h.next = now;
    let failed = run() {
        let pem, renew = cached(s);
        let from, to, ok = validity(chain_of(pem));
        if pem.len > 0 && ok && to > now {
            install(p, h, pem);
            h.next = renew;
            log_certificate(h, to, renew, now, "cached");
        }
    };
    for e in failed { write_stderr(str("ACME: ", h.names, ": the cache: ", e.message, "\n")); }
}

fn obtain(p: const Plan&, h: Held&, seats: Seats&) {
    var contacts: (const u8[:])[>..] = [];
    var domains: (const u8[:])[>..] = [];
    let s = settings_of(p, h.names, contacts, domains);
    var not_after = 0;
    var renew_at = 0;
    let failed = run() {
        var io = if p.ca.len > 0 { socket(p.ca, 10000) } else { socket(10000) };
        let errors = run() {
            let pem, renew = certificate(io, seats, s);
            let from, to, ok = validity(chain_of(pem));
            install(p, h, pem);
            not_after = to;
            renew_at = renew;
        };
        free(io);
        for e in errors { fail(e.message); }
    };
    let now = time() as i64;
    if failed.len == 0 {
        h.failures = 0;
        h.next = renew_at;
        log_certificate(h, not_after, renew_at, now, "issued");
        each_split(h.names, ' ') { broadcast(seats, CERT, h.ctx, it); };
        return;
    }
    h.failures++;
    let wait = min(60 << min(h.failures - 1, 6), 3600);
    h.next = now + wait;
    for e in failed { write_stderr(str("ACME: ", h.names, ": ", e.message, "; trying again in ", wait, " s\n")); }
}

// Makes h's context from pem, in place of the one it had.
fn install(p: const Plan&, h: Held&, pem: const u8[:]) {
    var protocols: (const u8[:])[>..] = [];
    each_split(p.protocols, ',') { if it.len > 0 { protocols.push(it); } };
    if protocols.len == 0 { protocols.push("h2"); protocols.push("http/1.1"); }
    let ctx, ok = tls::server(chain_of(pem), key_of(pem), protocols);
    guard ok else { fail(str("a server context from the certificate: ", tls::error_text())); }
    if tls::ok(h.ctx) { tls::free(h.ctx); }
    h.ctx = ctx;
}

fn log_certificate(h: const Held&, not_after: i64, renew_at: i64, now: i64, how: const u8[:]) {
    write_stderr(str("ACME: ", h.names, ": certificate ", how, ", valid for ", days(not_after - now),
                     ", renewing in ", days(renew_at - now), "\n"));
}

fn days(seconds: i64) -> u8[>..] {
    if seconds >= 2 * 86400 { return str(seconds / 86400, " days"); }
    return str(max(seconds, 0), " s");
}

fn acme::challenge_start(seats: const acme::Seats&, name, cert: const u8[:], key: const u8[:]) {
    let ctx, ok = tls::server(cert, key, [acme::ACME_TLS]);
    guard ok else { acme::fail(str("a context for the challenge for ", name, ": ", tls::error_text())); }
    acme::broadcast(seats, acme::CHALLENGE, ctx, name);
    tls::free(ctx);
}

fn acme::challenge_end(seats: const acme::Seats&, name: const u8[:]) {
    acme::broadcast(seats, acme::CHALLENGE_END, tls::Context { .. }, name);
}
