// A cache rustls-acme wrote, read as goose-acme's own: the account key ring
// generated, as PKCS#8 DER (test/data/rustls-acme-account.der), and a
// certificate file of ring's key in PEM, a blank line, and a certificate made
// with openssl req -x509 for it, valid until 2049 (test/data/rustls-acme-cert.pem).
// The certificate serves from the cache with no request, its key matching;
// renewed, the order is signed with ring's account key.
import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.4";
import acme from "../../";
import check from "../";
import fake from "../";

fn main() {
    let dir = str(resource_dir(), "flow-rustls-cache");
    var names: u8[>..] = [];
    if list_dir(dir, names) {
        each_split(names, '\n') { if it.len > 0 { delete_file(str(dir, "/", it)); } };
        delete_dir(dir);
    }
    let contacts = ["mailto:ops@example.test"];
    let domains = ["example.test"];
    let s = acme::Settings { directory: fake::DIRECTORY, contacts: contacts, domains: domains, cache: dir };
    let account = embed_file("../data/rustls-acme-account.der");
    let cert = embed_file("../data/rustls-acme-cert.pem");
    make_dir(dir);
    write_file(acme::cache_path(dir, "account", contacts, fake::DIRECTORY), account);
    write_file(acme::cache_path(dir, "cert", domains, fake::DIRECTORY), cert);

    var site = fake::Site { .. };
    var ca = fake::ca(site);
    ca.authorized = true;
    let failed = acme::run() {
        let pem, renew = acme::certificate(ca, site, s);
        check::that("rustls-acme's certificate, from the cache", pem == cert);
        let ctx, ok = tls::server(acme::chain_of(pem), acme::key_of(pem), ["http/1.1"]);
        check::that("a server context from it, the key matching", ok);
        if ok { tls::free(ctx); }

        print("when due:");
        ca.clock = renew - (time() as i64) + 1;
        let renewed, renew2 = acme::certificate(ca, site, s);
        check::that("a new certificate", renewed != cert);
    };
    for e in failed { print("error: ", e.message); }
    check::eq("errors", failed.len, 0);

    var xy: u8[>..] = [];
    let failed2 = tls::run() {
        let k = tls::key_from_pem(acme::pem(account, acme::PRIVATE_KEY));
        xy.append(tls::public_xy(k));
        tls::free(k);
    };
    check::eq("errors", failed2.len, 0);
    let jwk = acme::jwk(xy);
    check::that("the account signed with ring's key", find(jwk, ca.jwk[..43]) > 0 && find(jwk, ca.jwk[44..]) > 0);
    check::eq("accounts", ca.accounts, 1);
}
