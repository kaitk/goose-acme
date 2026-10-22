// The whole flow against the fake CA: a certificate for two names, kept in the
// cache and served from it, renewed with the cached account once it is due,
// and the same with no cache.
import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import acme from "../../";
import check from "../";
import fake from "../";

fn main() {
    let dir = str(resource_dir(), "flow-order-cache");
    var names: u8[>..] = [];
    if list_dir(dir, names) {
        each_split(names, '\n') { if it.len > 0 { delete_file(str(dir, "/", it)); } };
        delete_dir(dir);
    }
    var site = fake::Site { .. };
    var ca = fake::ca(site);
    let contacts = ["mailto:ops@example.test"];
    let domains = ["example.test", "www.example.test"];
    let s = acme::Settings { directory: fake::DIRECTORY, contacts: contacts, domains: domains, cache: dir };

    print("first:");
    let failed = acme::run() {
        let none, zero = acme::cached(s);
        check::eq("nothing cached", none.len, 0);
        let pem, renew = acme::certificate(ca, site, s);
        let from, to, ok = acme::validity(acme::chain_of(pem));
        check::that("a certificate", ok);
        check::that("renewed two thirds in", renew == to - (to - from) / 3 && to - from == 90 * 86400 + 3600);
        check::that("the key first", starts_with(acme::key_of(pem), "-----BEGIN PRIVATE KEY-----"));
        check::that("then the chain", starts_with(acme::chain_of(pem), "-----BEGIN CERTIFICATE-----"));
        check::eq("accounts", ca.accounts, 1);
        check::eq("challenges served and ended", site.started * 10 + site.ended, 22);

        print("again, from the cache:");
        let again, renew2 = acme::certificate(ca, site, s);
        check::that("the same certificate", again == pem && renew2 == renew);

        print("when due:");
        ca.clock = renew - (time() as i64) + 1;
        let renewed, renew3 = acme::certificate(ca, site, s);
        check::that("a new certificate", renewed != pem && acme::chain_of(renewed) == ca.cert);
        check::eq("accounts, the cached key's found", ca.accounts, 1);
        let cached, renew4 = acme::cached(s);
        check::that("cached", cached == renewed && renew4 == renew3);
    };
    for e in failed { print("error: ", e.message); }
    check::eq("errors", failed.len, 0);

    print("no cache:");
    var site2 = fake::Site { .. };
    var ca2 = fake::ca(site2);
    ca2.authorized = true;
    let one = ["example.test"];
    let s2 = acme::Settings { directory: fake::DIRECTORY, domains: one, .. };
    let failed2 = acme::run() {
        let pem, renew = acme::certificate(ca2, site2, s2);
        check::that("a certificate, its authorization valid already", pem.len > 0 && site2.started == 0);
        let none, zero = acme::cached(s2);
        check::eq("nothing cached", none.len, 0);
    };
    for e in failed2 { print("error: ", e.message); }
    check::eq("errors", failed2.len, 0);
}
