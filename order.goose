// The flow (RFC 8555, section 7): the directory, the account, an order, a
// TLS-ALPN-01 challenge for each authorization, finalize with a CSR, and the
// chain. It runs on the program's io and challenges values, through these
// overloads:
//
//   acme::exchange(io, method, url, body, r: acme::Response&)
//       one HTTPS request: GET, HEAD, or a POST of body as JOSE; the response
//       into r, or acme::fail when there is none (https.goose has https,
//       which carries one over a transport)
//   acme::wait(io, seconds)        before polling a status again
//   acme::now(io) -> i64           seconds since the epoch
//   acme::challenge_start(challenges, name, certificate_pem, key_pem)
//       answer a TLS-ALPN-01 handshake for name with this certificate, from
//       now until challenge_end
//   acme::challenge_end(challenges, name)
//
// Each call is blocking, so the flow runs where blocking is allowed, such as
// on a lane.
namespace acme;

import std;
import json;
import tls from "github.com/kaitk/goose-tls@v0.0.5";

// How many times a status is polled, and how long to wait between polls when
// the CA's Retry-After doesn't say, and at most when it does.
let POLLS = 30;
let POLL_WAIT = 2;
let MAX_POLL_WAIT = 60;

// A session with the CA: the directory's URLs, the account, and the nonce for
// the next request.
struct Session {
    new_nonce: u8[..1024],
    new_account: u8[..1024],
    new_order: u8[..1024],
    key: tls::Key,
    jwk: u8[..256],
    thumbprint: u8[..64],
    kid: u8[..1024],
    nonce: u8[..256],
}

// The certificate s.cache holds for s.domains from s.directory, and when to
// renew it: two thirds into its validity, as rustls-acme renews. "" and 0 when
// there is none, or it can't be read. Makes no request.
fn cached(s) -> u8[>..], i64 {
    var pem: u8[>..] = [];
    guard s.cache.len > 0 else { return pem, 0; }
    cache_open(s.cache);
    let path = cache_path(s.cache, "cert", s.domains, s.directory);
    guard cache_load(path, pem) else { return pem, 0; }
    let from, to, ok = validity(chain_of(pem));
    guard ok && key_of(pem).len > 0 else { pem.clear(); return pem, 0; }
    return pem, renew_time(from, to);
}

// A certificate for s.domains: the cached one while it is before its renewal
// time, or a new one from s.directory, which the cache then keeps. Returns
// the PEM as the cache keeps it (key_of and chain_of split it) and when to
// renew it. Leaves through acme::fail when the CA refuses or can't be reached;
// the program keeps serving what it has, and calls again later.
fn certificate<I, C>(io: I&, challenges: C&, s: Settings) -> u8[>..], i64 {
    guard s.domains.len > 0 else { fail("no domains to get a certificate for"); }
    {
        let pem, renew = cached(s);
        if pem.len > 0 && now(io) < renew { return copy(pem), renew; }
    }
    let pem = order(io, challenges, s);
    let from, to, ok = validity(chain_of(pem));
    guard ok else { fail("the CA's certificate has no validity that can be read"); }
    if s.cache.len > 0 { cache_store(s.cache, cache_path(s.cache, "cert", s.domains, s.directory), pem); }
    return copy(pem), renew_time(from, to);
}

fn renew_time(from: i64, to: i64) -> i64 { to - (to - from) / 3 }

fn order<I, C>(io: I&, challenges: C&, s: Settings) -> u8[>..] {
    var ses = Session { .. };
    var r = Response { .. };
    exchange(io, "GET", s.directory, "", r);
    expect(r, 200, 200, s.directory);
    parsed(r.body, s.directory) { root =>
        ses.new_nonce.append(text(root, "newNonce"));
        ses.new_account.append(text(root, "newAccount"));
        ses.new_order.append(text(root, "newOrder"));
    };
    guard ses.new_nonce.len > 0 && ses.new_account.len > 0 && ses.new_order.len > 0 else {
        fail(str(s.directory, " lacks newNonce, newAccount, or newOrder"));
    }
    account(io, ses, s, r);

    var payload: u8[>..] = [];
    payload.append("{\"identifiers\":[");
    for d, i in s.domains {
        if i > 0 { payload.push(','); }
        payload.append("{\"type\":\"dns\",\"value\":");
        json::format_string(payload, d);
        payload.push('}');
    }
    payload.append("]}");
    post(io, ses, ses.new_order, payload, r);
    expect(r, 201, 201, "newOrder");
    guard r.location.len > 0 else { fail("newOrder gave no order URL"); }
    var order_url: u8[..1024] = [];
    order_url.append(r.location);
    var finalize: u8[..1024] = [];
    var authorizations: u8[>..] = [];
    parsed(r.body, "newOrder") { root =>
        finalize.append(text(root, "finalize"));
        let list = json::member(root, "authorizations");
        if list {
            json::each(list) { a =>
                let url, ok = json::as_string(a);
                if ok { authorizations.append(url); authorizations.push('\n'); }
            };
        }
    };
    guard finalize.len > 0 else { fail("the order has no finalize URL"); }
    each_split(authorizations, '\n') { url =>
        if url.len > 0 { authorize(io, challenges, ses, url, r); }
    };

    let status = poll(io, ses, order_url, "processing", r);
    guard status == "ready" else { fail(str("the order is ", status, problem_of(r.body))); }
    var key_pem: u8[>..] = [];
    var csr: u8[>..] = [];
    let failed = tls::run() {
        let k = tls::key_generate(tls::P256);
        key_pem.append(tls::key_pem(k));
        csr.append(tls::csr(k, s.domains));
        tls::free(k);
    };
    for e in failed { fail(str("the certificate's key: ", e.message)); }
    payload.clear();
    payload.append("{\"csr\":\"");
    base64url(payload, csr);
    payload.append("\"}");
    post(io, ses, finalize, payload, r);
    expect(r, 200, 200, "finalize");
    let done = poll(io, ses, order_url, "processing", r);
    guard done == "valid" else { fail(str("the order is ", done, problem_of(r.body))); }
    var certificate_url: u8[..1024] = [];
    parsed(r.body, "the order") { root => certificate_url.append(text(root, "certificate")); };
    guard certificate_url.len > 0 else { fail("the valid order has no certificate URL"); }
    post(io, ses, certificate_url, "", r);
    expect(r, 200, 200, "the certificate");
    tls::free(ses.key);

    var pem: u8[>..] = [];
    pem.append(key_pem);
    pem.push('\n');
    pem.append(r.body);
    return pem;
}

// Loads the account key from the cache, or makes one and caches it, then
// finds or creates the account, whose URL signs every request after.
fn account<I>(io: I&, ses: Session&, s: Settings, r: Response&) {
    var der: u8[>..] = [];
    var path: u8[>..] = [];
    if s.cache.len > 0 { path.append(cache_path(s.cache, "account", s.contacts, s.directory)); }
    let have = path.len > 0 && cache_load(path, der);
    var xy: u8[>..] = [];
    var made: u8[>..] = [];
    let failed = tls::run() {
        ses.key = if have { tls::key_from_pem(pem(der, PRIVATE_KEY)) } else { tls::key_generate(tls::P256) };
        xy.append(tls::public_xy(ses.key));
        if !have { made.append(tls::key_pem(ses.key)); }
    };
    for e in failed { fail(str("the account key: ", e.message)); }
    if !have && path.len > 0 {
        let pkcs8, end, ok = pem_block(made, 0, PRIVATE_KEY);
        guard ok else { fail("the account key's PEM can't be read"); }
        cache_store(s.cache, path, pkcs8);
    }
    ses.jwk.append(jwk(xy));
    ses.thumbprint.append(thumbprint(ses.jwk));

    var payload: u8[>..] = [];
    payload.append("{\"termsOfServiceAgreed\":true,\"contact\":[");
    for c, i in s.contacts {
        if i > 0 { payload.push(','); }
        json::format_string(payload, c);
    }
    payload.append("]}");
    post(io, ses, ses.new_account, payload, r);
    expect(r, 200, 201, "newAccount");
    guard r.location.len > 0 else { fail("newAccount gave no account URL"); }
    ses.kid.append(r.location);
}

// Answers the authorization at url's TLS-ALPN-01 challenge, unless it is
// valid already, and waits for the CA to validate it. The challenge is served
// only while this runs, failing or not.
fn authorize<I, C>(io: I&, challenges: C&, ses: Session&, url: const u8[:], r: Response&) {
    post(io, ses, url, "", r);
    expect(r, 200, 200, url);
    var name: u8[..256] = [];
    var status: u8[..16] = [];
    var challenge: u8[..1024] = [];
    var token: u8[..256] = [];
    parsed(r.body, url) { root =>
        status.append(text(root, "status"));
        name.append(text(json::member(root, "identifier"), "value"));
        let list = json::member(root, "challenges");
        if list {
            json::each(list) { c =>
                if text(c, "type") == "tls-alpn-01" && challenge.len == 0 {
                    challenge.append(text(c, "url"));
                    token.append(text(c, "token"));
                }
            };
        }
    };
    if status == "valid" { return; }
    guard status == "pending" else { fail(str("the authorization for ", name, " is ", status)); }
    guard challenge.len > 0 && token.len > 0 && name.len > 0 else {
        fail(str("the authorization for ", name, " offers no tls-alpn-01 challenge"));
    }

    let digest = key_authorization_digest(token, ses.thumbprint);
    var cert: u8[>..] = [];
    var key_pem: u8[>..] = [];
    let failed = tls::run() {
        let k = tls::key_generate(tls::P256);
        cert.append(tls::challenge_certificate(k, name, digest));
        key_pem.append(tls::key_pem(k));
        tls::free(k);
    };
    for e in failed { fail(str("the challenge certificate for ", name, ": ", e.message)); }

    challenge_start(challenges, name, cert, key_pem);
    var outcome: u8[..16] = [];
    let errors = run() {
        post(io, ses, challenge, "{}", r);
        expect(r, 200, 200, challenge);
        outcome.append(poll(io, ses, url, "pending", r));
    };
    challenge_end(challenges, name);
    for e in errors { fail(e.message); }
    guard outcome == "valid" else {
        var why: u8[>..] = [];
        parsed(r.body, url) { root =>
            let list = json::member(root, "challenges");
            if list {
                json::each(list) { c =>
                    if text(c, "type") == "tls-alpn-01" {
                        let e = json::member(c, "error");
                        if e { format(why, ": ", text(e, "type"), " ", text(e, "detail")); }
                    }
                };
            }
        };
        fail(str("the challenge for ", name, " is ", outcome, why));
    }
}

// POST-as-GETs url until its status is no longer while, and returns that
// status, with the last response in r.
fn poll<I>(io: I&, ses: Session&, url: const u8[:], pending: const u8[:], r: Response&) -> u8[..16] {
    var status: u8[..16] = [];
    for i in POLLS {
        post(io, ses, url, "", r);
        expect(r, 200, 200, url);
        status.clear();
        parsed(r.body, url) { root => status.append(text(root, "status")); };
        guard status == pending else { return status; }
        wait(io, if r.retry_after > 0 { min(r.retry_after, MAX_POLL_WAIT) } else { POLL_WAIT });
    }
    fail(str(url, " is still ", pending, " after ", POLLS, " polls"));
}

// Sends payload to url as the account, signed with a fresh nonce, and gives
// the response in r. A badNonce answer is retried with the nonce it carries,
// as RFC 8555, section 6.5, allows.
fn post<I>(io: I&, ses: Session&, url: const u8[:], payload: const u8[:], r: Response&) {
    for attempt in 3 {
        if ses.nonce.len == 0 {
            exchange(io, "HEAD", ses.new_nonce, "", r);
            guard (r.status == 200 || r.status == 204) && r.nonce.len > 0 else {
                fail(str("newNonce gave no nonce (HTTP ", r.status, ")"));
            }
            ses.nonce.append(r.nonce);
        }
        let body = signed(ses.key, ses.jwk, ses.kid, ses.nonce, url, payload);
        exchange(io, "POST", url, body, r);
        ses.nonce.clear();
        ses.nonce.append(r.nonce);
        guard r.status == 400 && problem_type(r.body) == "urn:ietf:params:acme:error:badNonce" else { return; }
    }
}

// Fails unless r's status is lo or hi, with the CA's problem document.
fn expect(r, lo: i64, hi: i64, what: const u8[:]) {
    guard r.status != lo && r.status != hi else { return; }
    fail(str(what, ": HTTP ", r.status, problem_of(r.body)));
}

// ": type detail" from a problem document (RFC 7807), or "".
fn problem_of(body: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(body, doc, decoded);
    if root {
        let t = text(root, "type");
        let d = text(root, "detail");
        if t.len > 0 || d.len > 0 { format(out, ": ", t, if t.len > 0 && d.len > 0 { " " } else { "" }, d); }
    }
    return out;
}

fn problem_type(body: const u8[:]) -> u8[..128] {
    var out: u8[..128] = [];
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(body, doc, decoded);
    if root {
        let t = text(root, "type");
        if t.len <= 128 { out.append(t); }
    }
    return out;
}

// Parses body as JSON and hands its root to F, or fails naming what.
fn parsed<F>(body: const u8[:], what: const u8[:]) {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(body, doc, decoded);
    guard root else { fail(str(what, ": ", err)); }
    F(root);
}

// The string member key of n, or "" when n is null or it isn't a string.
fn text(n: json::Node?, key: const u8[:]) -> const u8[:] {
    let s, ok = json::as_string(json::member(n, key));
    return if ok { s } else { "" };
}
