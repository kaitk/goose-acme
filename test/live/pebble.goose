// A certificate from Pebble over acme.socket, its TLS-ALPN-01 challenges
// answered by scripts/challenge.py from the files this program writes; then
// the same certificate from the cache, and, once it is due, a new one with
// the cached account. scripts/pebble.sh runs it, with Pebble's certificates
// lasting 30 seconds, and passes the settings below in the environment.
import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.4";
import http from "github.com/kaitk/goose-http@v0.5.0";
import acme from "../../";
import acme.socket;
import check from "../";

// The challenges: each a certificate and key in dir, named after the
// identifier, for scripts/challenge.py to serve.
struct Files { dir: u8[..1024] }

fn acme::challenge_start(f: Files&, name: const u8[:], cert: const u8[:], key: const u8[:]) {
    write_file(str(f.dir, "/", name, ".key"), key);
    write_file(str(f.dir, "/", name, ".crt"), cert);
}

fn acme::challenge_end(f: Files&, name: const u8[:]) {
    delete_file(str(f.dir, "/", name, ".crt"));
    delete_file(str(f.dir, "/", name, ".key"));
}

fn setting(name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    if !env(name, v) { abort(str(name, " is not set: run scripts/pebble.sh")); }
    return v;
}

fn main() {
    let directory = setting("PEBBLE_DIRECTORY");
    var ca: u8[>..] = [];
    guard read_file(setting("PEBBLE_CA"), ca) else { abort("can't read PEBBLE_CA"); }
    let cache = setting("ACME_CACHE");
    var files = Files { .. };
    files.dir.append(setting("CHALLENGE_DIR"));
    let contacts = ["mailto:ops@acme.test"];
    let domains = ["acme.test", "www.acme.test"];
    let s = acme::Settings { directory: directory, contacts: contacts, domains: domains, cache: cache };

    var first: u8[>..] = [];
    var renew_at = 0;
    let failed = acme::run() {
        var io = acme::socket(ca, 10000);
        let pem, renew = acme::certificate(io, files, s);
        first.append(pem);
        renew_at = renew;
        acme::free(io);
    };
    for e in failed { print("error: ", e.message); }
    check::eq("errors", failed.len, 0);
    let from, to, ok = acme::validity(acme::chain_of(first));
    check::that("a certificate", ok && first.len > 0);
    check::that("lasting Pebble's 30 seconds", to - from >= 29 && to - from <= 31);
    check::that("with its issuer", find(acme::chain_of(first)[100..], "-----BEGIN CERTIFICATE-----") > 0);
    let ctx, loads = tls::server(acme::chain_of(first), acme::key_of(first), ["http/1.1"]);
    check::that("a server context from it, the key matching", loads);
    if loads { tls::free(ctx); }
    check::that("no challenge files left", list_count(files.dir) == 0);

    let failed2 = acme::run() {
        var io = acme::socket(ca, 10000);
        let pem, renew = acme::certificate(io, files, s);
        check::that("the same, from the cache", pem == first && renew == renew_at);
        acme::free(io);
    };
    check::eq("errors", failed2.len, 0);

    let wait = renew_at - (time() as i64) + 1;
    if wait > 0 { sleep_ms(wait * 1000); }
    let failed3 = acme::run() {
        var io = acme::socket(ca, 10000);
        let pem, renew = acme::certificate(io, files, s);
        check::that("renewed when due", pem != first && renew > renew_at);
        acme::free(io);
    };
    for e in failed3 { print("error: ", e.message); }
    check::eq("errors", failed3.len, 0);
    check::eq("cached files, one account and one certificate", list_count(cache), 2);
}

fn list_count(dir: const u8[:]) -> i64 {
    var names: u8[>..] = [];
    list_dir(dir, names);
    var n = 0;
    each_split(names, '\n') { if it.len > 0 && !ends_with(it, ".tmp") { n++; } };
    return n;
}
