// A cache in the layout of Go's autocert.DirCache, as Thruster keeps it: one
// that autocert wrote (test/data/autocert/, made through autocert.DirCache:
// the account key and a certificate's key as SEC 1's EC PRIVATE KEY, and a
// self-signed certificate valid until 2049) serves with no request; renewed,
// the order is signed with autocert's account key and the file is rewritten
// as autocert reads it. In an empty directory, the account key and the
// certificate are stored under autocert's names. Then an account bound to
// the CA's with EAB, and the binding's failures.
import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.6";
import acme from "../../";
import check from "../";
import fake from "../";

let ACCOUNT = embed_file("../data/autocert/acme_account+key");
let CERT = embed_file("../data/autocert/example.test");

fn clean(dir: const u8[:]) {
    var names: u8[>..] = [];
    if list_dir(dir, names) {
        each_split(names, '\n') { if it.len > 0 { delete_file(str(dir, "/", it)); } };
        delete_dir(dir);
    }
}

fn listing(dir: const u8[:]) -> u8[>..] {
    var names: u8[>..] = [];
    list_dir(dir, names);
    var out: u8[>..] = [];
    each_split(names, '\n') {
        if it.len > 0 && !ends_with(it, ".tmp") { if out.len > 0 { out.append(", "); } out.append(it); }
    };
    return out;
}

fn read(path: const u8[:]) -> u8[>..] {
    var data: u8[>..] = [];
    read_file(path, data);
    return data;
}

fn main() {
    let dir = str(resource_dir(), "flow-autocert-cache");
    clean(dir);
    make_dir(dir);
    write_file(str(dir, "/acme_account+key"), ACCOUNT);
    write_file(str(dir, "/example.test"), CERT);
    let one = ["example.test"];
    let none: (const u8[:])[] = [];
    let s = acme::Settings { directory: fake::DIRECTORY, contacts: none, domains: one, cache: dir, autocert: true };

    var site = fake::Site { .. };
    var ca = fake::ca(site);
    ca.authorized = true;
    print("autocert's cache:");
    let failed = acme::run() {
        let pem, renew = acme::certificate(ca, site, s);
        check::that("autocert's certificate, from the cache", pem == CERT);
        check::that("its key, SEC 1's", starts_with(acme::key_of(pem), "-----BEGIN EC PRIVATE KEY-----"));
        check::that("then the chain", starts_with(acme::chain_of(pem), "-----BEGIN CERTIFICATE-----"));
        let ctx, ok = tls::server(acme::chain_of(pem), acme::key_of(pem), ["http/1.1"]);
        check::that("a server context from it, the key matching", ok);
        if ok { tls::free(ctx); }

        print("when due:");
        ca.clock = renew - (time() as i64) + 1;
        let renewed, renew2 = acme::certificate(ca, site, s);
        let file = read(str(dir, "/example.test"));
        check::that("a new certificate, in the domain's file", renewed != CERT && file == renewed);
        check::that("the key, then the chain with nothing after it",
                    starts_with(renewed, "-----BEGIN PRIVATE KEY-----") &&
                    find(renewed, "-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----") > 0 &&
                    ends_with(renewed, "-----END CERTIFICATE-----\n"));
        check::that("the chain as the CA gave it", acme::chain_of(renewed) == ca.cert);
        check::that("the account key kept", read(str(dir, "/acme_account+key")) == ACCOUNT);
    };
    for e in failed { print("error: ", e.message); }
    check::eq("errors", failed.len, 0);

    var xy: u8[>..] = [];
    let failed2 = tls::run() {
        let k = tls::key_from_pem(ACCOUNT);
        xy.append(tls::public_xy(k));
        tls::free(k);
    };
    check::eq("errors", failed2.len, 0);
    let jwk = acme::jwk(xy);
    check::that("the order signed with autocert's account key", find(jwk, ca.jwk[..43]) > 0 && find(jwk, ca.jwk[44..]) > 0);
    check::eq("accounts", ca.accounts, 1);

    print("an empty cache:");
    clean(dir);
    var site2 = fake::Site { .. };
    var ca2 = fake::ca(site2);
    ca2.authorized = true;
    let failed3 = acme::run() {
        let pem, renew = acme::certificate(ca2, site2, s);
        check::text("files", listing(dir), "acme_account+key, example.test");
        check::that("the account key as PKCS#8 PEM", starts_with(read(str(dir, "/acme_account+key")), "-----BEGIN PRIVATE KEY-----"));
        let again, renew2 = acme::cached(s);
        check::that("the certificate, from the cache", again == pem && renew2 == renew);
    };
    for e in failed3 { print("error: ", e.message); }
    check::eq("errors", failed3.len, 0);

    print("a domain that isn't a file name:");
    let slash = ["../example.test"];
    let s3 = acme::Settings { directory: fake::DIRECTORY, contacts: none, domains: slash, cache: dir, autocert: true };
    let failed4 = acme::run() { let pem, renew = acme::certificate(ca2, site2, s3); };
    for e in failed4 { print("error: ", e.message); }
    check::eq("errors", failed4.len, 1);
    clean(dir);

    print("EAB:");
    var site3 = fake::Site { .. };
    var ca3 = fake::ca(site3);
    ca3.authorized = true;
    ca3.eab_kid.append("kid-1");
    // The key's bytes are 0 to 31: AAECAw... in base64url.
    for i in 32 { ca3.eab_key.push(i as u8); }
    let key64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let bound = acme::Settings { directory: fake::DIRECTORY, contacts: none, domains: one, eab_kid: "kid-1", eab_key: key64 };
    let failed5 = acme::run() {
        let pem, renew = acme::certificate(ca3, site3, bound);
        check::that("a certificate for the bound account", pem.len > 0);
    };
    for e in failed5 { print("error: ", e.message); }
    check::eq("errors", failed5.len, 0);

    let unbound = acme::Settings { directory: fake::DIRECTORY, contacts: none, domains: one };
    let wrong = acme::Settings { directory: fake::DIRECTORY, contacts: none, domains: one, eab_kid: "kid-1",
                                 eab_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh4" };
    let half = acme::Settings { directory: fake::DIRECTORY, contacts: none, domains: one, eab_kid: "kid-1" };
    let bad = acme::Settings { directory: fake::DIRECTORY, contacts: none, domains: one, eab_kid: "kid-1", eab_key: "a+b/" };
    for t in [unbound, wrong, half, bad] {
        let failed6 = acme::run() { let pem, renew = acme::certificate(ca3, site3, t); };
        for e in failed6 { print("error: ", e.message); }
        check::eq("errors", failed6.len, 1);
    }
}
