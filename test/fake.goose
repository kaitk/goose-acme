// A CA faked in the program, for the flow's tests: an io whose exchange
// answers as an ACME server would, and a challenges value that records what it
// was asked to serve. The CA checks each JWS's nonce, URL, and key or account,
// and that a challenge is served when it is answered; it doesn't check
// signatures, which the live test against Pebble does. Each request is
// printed, for the test's golden file.
namespace fake;

import std;
import base64;
import json;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.4";
import acme from "../";

let BASE = "https://ca.test";
let DIRECTORY = "https://ca.test/dir";

// What the program serves for TLS-ALPN-01: the names, newline-separated.
struct Site { serving: u8[..512], started: i64 = 0, ended: i64 = 0 }

struct Ca {
    site: Site&,
    // Seconds added to the real time, which wait advances.
    clock: i64 = 0,
    // The last nonce issued; requests must carry it.
    nonce: i64 = 0,
    // Scenarios: refuse this many good nonces as bad; fail every challenge;
    // start with every authorization valid; refuse the order.
    bad_nonces: i64 = 0,
    fail_challenge: bool = false,
    authorized: bool = false,
    refuse_order: bool = false,
    // The account: its JWK, and how many accounts were made.
    jwk: u8[..256],
    accounts: i64 = 0,
    // The order: its names, newline-separated; the names validated; the
    // names whose challenge failed; polls left before a challenge is valid.
    domains: u8[..512],
    valid: u8[..512],
    invalid: u8[..512],
    processing: i64 = 0,
    finalized: bool = false,
    cert: u8[..8192],
}

fn ca(site: Site&) -> Ca { Ca { site: site, .. } }

fn has(list: const u8[:], name: const u8[:]) -> bool {
    var found = false;
    each_split(list, '\n') { if it == name { found = true; } };
    return found;
}

fn acme::challenge_start(site: fake::Site&, name: const u8[:], cert: const u8[:], key: const u8[:]) {
    // goose-tls dates a certificate from an hour before it was made.
    let from, to, ok = acme::validity(cert);
    let good = ok && to - from == 7 * 86400 + 3600 && starts_with(key, "-----BEGIN PRIVATE KEY-----");
    print("  serve ", name, if good { " (a 7-day certificate and its key)" } else { " (a malformed certificate): FAILED" });
    assert(good);
    site.serving.append(name);
    site.serving.push('\n');
    site.started++;
}

fn acme::challenge_end(site: fake::Site&, name: const u8[:]) {
    print("  stop ", name);
    var rest: u8[..512] = [];
    each_split(site.serving, '\n') { if it.len > 0 && it != name { rest.append(it); rest.push('\n'); } };
    site.serving.clear();
    site.serving.append(rest);
    site.ended++;
}

fn acme::wait(c: fake::Ca&, seconds: i64) {
    print("  wait ", seconds);
    c.clock += seconds;
}

fn acme::now(c: fake::Ca&) -> i64 { fake::now(c) }

fn now(c: Ca&) -> i64 { time() as i64 + c.clock }

fn unbase64url(s: const u8[:]) -> u8[>..], bool {
    var t: u8[>..] = [];
    for b in s { t.push(if b == '-' { '+' } else if b == '_' { '/' } else { b }); }
    while t.len % 4 != 0 { t.push('='); }
    var out: u8[>..] = [];
    let ok = base64::decode(out, t);
    return out, ok;
}

fn reply(c: Ca&, r: acme::Response&, status: i64, body: const u8[:]) {
    r.status = status;
    c.nonce++;
    format(r.nonce, "n", c.nonce);
    r.body.append(body);
}

fn problem(c: Ca&, r: acme::Response&, status: i64, kind: const u8[:], detail: const u8[:]) {
    reply(c, r, status, str("{\"type\":\"urn:ietf:params:acme:error:", kind, "\",\"detail\":\"", detail, "\"}"));
}

fn acme::exchange(c: fake::Ca&, method: const u8[:], url: const u8[:], body: const u8[:], r: acme::Response&) {
    fake::answer(c, method, url, body, r);
}

fn answer(c: Ca&, method: const u8[:], url: const u8[:], body: const u8[:], r: acme::Response&) {
    acme::reset(r);
    guard starts_with(url, BASE) else { acme::fail(str("fake: no such host in ", url)); }
    let path = url[BASE.len..];
    print("  ", method, " ", path);
    if method == "GET" && path == "/dir" {
        reply(c, r, 200, str("{\"newNonce\":\"", BASE, "/nonce\",\"newAccount\":\"", BASE,
                             "/account\",\"newOrder\":\"", BASE, "/order\",\"meta\":{}}"));
        return;
    }
    if method == "HEAD" && path == "/nonce" {
        reply(c, r, 200, "");
        return;
    }
    guard method == "POST" else { problem(c, r, 405, "malformed", "method"); return; }

    // The JWS: its protected header, and its payload.
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(body, doc, decoded);
    guard root else { problem(c, r, 400, "malformed", "not JSON"); return; }
    let p64, p_ok = json::as_string(json::member(root, "protected"));
    let b64, b_ok = json::as_string(json::member(root, "payload"));
    let s64, s_ok = json::as_string(json::member(root, "signature"));
    let header, h_ok = unbase64url(p64);
    let payload, y_ok = unbase64url(b64);
    let signature, g_ok = unbase64url(s64);
    guard p_ok && b_ok && s_ok && h_ok && y_ok && g_ok && signature.len == 64 else {
        problem(c, r, 400, "malformed", "not a flattened JWS"); return;
    }
    var hdoc: json::Node[>..] = [];
    var hdecoded: u8[>..] = [];
    let h, herr = json::parse(header, hdoc, hdecoded);
    guard h else { problem(c, r, 400, "malformed", "the protected header"); return; }
    let alg, a_ok = json::as_string(json::member(h, "alg"));
    let nonce, n_ok = json::as_string(json::member(h, "nonce"));
    let hurl, u_ok = json::as_string(json::member(h, "url"));
    let kid, k_ok = json::as_string(json::member(h, "kid"));
    let jwk = json::member(h, "jwk");
    guard a_ok && alg == "ES256" && u_ok && hurl == url else { problem(c, r, 400, "malformed", "alg or url"); return; }
    guard n_ok && nonce == str("n", c.nonce) else { problem(c, r, 400, "badNonce", "a stale nonce"); return; }
    if c.bad_nonces > 0 {
        c.bad_nonces--;
        problem(c, r, 400, "badNonce", "refused for the test");
        return;
    }

    if path == "/account" {
        guard jwk && !k_ok else { problem(c, r, 400, "malformed", "newAccount takes a jwk"); return; }
        var pdoc: json::Node[>..] = [];
        var pdecoded: u8[>..] = [];
        let pl, perr = json::parse(payload, pdoc, pdecoded);
        let tos, t_ok = json::as_bool(json::member(pl, "termsOfServiceAgreed"));
        guard t_ok && tos else { problem(c, r, 400, "malformed", "terms not agreed"); return; }
        let x, x_ok = json::as_string(json::member(jwk, "x"));
        let y, y_ok = json::as_string(json::member(jwk, "y"));
        guard x_ok && y_ok else { problem(c, r, 400, "malformed", "the jwk"); return; }
        var key: u8[>..] = [];
        format(key, x, ".", y);
        r.location.append(str(BASE, "/acct/1"));
        if c.jwk == key { reply(c, r, 200, "{\"status\":\"valid\"}"); return; }
        c.jwk.clear();
        c.jwk.append(key);
        c.accounts++;
        reply(c, r, 201, "{\"status\":\"valid\"}");
        return;
    }
    guard k_ok && kid == str(BASE, "/acct/1") && !jwk else { problem(c, r, 401, "unauthorized", "no account"); return; }

    if path == "/order" {
        if c.refuse_order { problem(c, r, 403, "rejectedIdentifier", "the test refuses it"); return; }
        var pdoc: json::Node[>..] = [];
        var pdecoded: u8[>..] = [];
        let pl, perr = json::parse(payload, pdoc, pdecoded);
        let ids = json::member(pl, "identifiers");
        guard ids else { problem(c, r, 400, "malformed", "no identifiers"); return; }
        c.domains.clear();
        c.valid.clear();
        c.invalid.clear();
        c.finalized = false;
        json::each(ids) { id =>
            let v, ok = json::as_string(json::member(id, "value"));
            if ok { c.domains.append(v); c.domains.push('\n'); }
            if ok && c.authorized { c.valid.append(v); c.valid.push('\n'); }
        };
        r.location.append(str(BASE, "/order/1"));
        reply(c, r, 201, order_body(c));
        return;
    }
    guard b64.len == 0 || starts_with(path, "/chal/") || starts_with(path, "/finalize/") else {
        problem(c, r, 400, "malformed", "a POST-as-GET with a payload"); return;
    }
    if starts_with(path, "/authz/") {
        let name = path[7..];
        guard has(c.domains, name) else { problem(c, r, 404, "malformed", "no such authorization"); return; }
        if c.processing > 0 && !has(c.valid, name) && !has(c.invalid, name) {
            c.processing--;
            if c.processing == 0 {
                if c.fail_challenge { c.invalid.append(name); c.invalid.push('\n'); }
                else { c.valid.append(name); c.valid.push('\n'); }
            }
        }
        r.retry_after = 1;
        reply(c, r, 200, authz_body(c, name));
        return;
    }
    if starts_with(path, "/chal/") {
        let name = path[6..];
        guard has(c.domains, name) else { problem(c, r, 404, "malformed", "no such challenge"); return; }
        guard has(c.site.serving, name) else { problem(c, r, 400, "connection", "nothing serves the challenge"); return; }
        c.processing = 2;
        reply(c, r, 200, "{\"type\":\"tls-alpn-01\",\"status\":\"processing\"}");
        return;
    }
    if path == "/order/1" {
        if c.finalized && c.processing > 0 { c.processing--; }
        reply(c, r, 200, order_body(c));
        return;
    }
    if path == "/finalize/1" {
        var pdoc: json::Node[>..] = [];
        var pdecoded: u8[>..] = [];
        let pl, perr = json::parse(payload, pdoc, pdecoded);
        let csr64, ok = json::as_string(json::member(pl, "csr"));
        let csr, csr_ok = unbase64url(csr64);
        guard ok && csr_ok && csr.len > 100 else { problem(c, r, 400, "badCSR", "no CSR"); return; }
        var names: (const u8[:])[>..] = [];
        each_split(c.domains, '\n') { if it.len > 0 { names.push(it); } };
        let failed = tls::run() {
            let k = tls::key_generate(tls::P256);
            c.cert.clear();
            c.cert.append(tls::self_signed(k, names, 90));
            tls::free(k);
        };
        for e in failed { acme::fail(str("fake: the certificate: ", e.message)); }
        c.finalized = true;
        c.processing = 1;
        reply(c, r, 200, order_body(c));
        return;
    }
    if path == "/cert/1" {
        guard c.finalized && c.processing == 0 else { problem(c, r, 404, "malformed", "no certificate yet"); return; }
        reply(c, r, 200, c.cert);
        return;
    }
    problem(c, r, 404, "malformed", "no such resource");
}

fn order_body(c: Ca&) -> u8[>..] {
    var all_valid = true;
    var any_invalid = false;
    each_split(c.domains, '\n') {
        if it.len > 0 && !has(c.valid, it) { all_valid = false; }
        if it.len > 0 && has(c.invalid, it) { any_invalid = true; }
    };
    let status = if any_invalid { "invalid" } else if !all_valid { "pending" }
                 else if !c.finalized { "ready" } else if c.processing > 0 { "processing" } else { "valid" };
    var out: u8[>..] = [];
    format(out, "{\"status\":\"", status, "\",\"authorizations\":[");
    var first = true;
    each_split(c.domains, '\n') {
        if it.len > 0 {
            if !first { out.push(','); }
            format(out, "\"", BASE, "/authz/", it, "\"");
            first = false;
        }
    };
    format(out, "],\"finalize\":\"", BASE, "/finalize/1\"");
    if status == "valid" { format(out, ",\"certificate\":\"", BASE, "/cert/1\""); }
    out.push('}');
    return out;
}

fn authz_body(c: Ca&, name: const u8[:]) -> u8[>..] {
    let status = if has(c.valid, name) { "valid" } else if has(c.invalid, name) { "invalid" } else { "pending" };
    var out: u8[>..] = [];
    format(out, "{\"identifier\":{\"type\":\"dns\",\"value\":\"", name, "\"},\"status\":\"", status,
           "\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"", BASE, "/http/", name,
           "\",\"token\":\"h\",\"status\":\"pending\"},{\"type\":\"tls-alpn-01\",\"url\":\"", BASE,
           "/chal/", name, "\",\"token\":\"tok-", name, "\",\"status\":\"", status, "\"");
    if status == "invalid" {
        out.append(",\"error\":{\"type\":\"urn:ietf:params:acme:error:incorrectResponse\",\"detail\":\"the test's answer\"}");
    }
    out.append("}]}");
    return out;
}
