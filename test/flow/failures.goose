// The flow's failures against the fake CA: nonces refused as bad and retried,
// a challenge the CA finds invalid, an order the CA refuses, a CA that can't
// be reached, no domains, and a cached certificate that can't be read.
import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import acme from "../../";
import check from "../";
import fake from "../";

fn attempt(label: const u8[:], ca: fake::Ca&, site: fake::Site&, s: acme::Settings) {
    print(label, ":");
    let failed = acme::run() {
        let pem, renew = acme::certificate(ca, site, s);
        check::that("a certificate", pem.len > 0);
    };
    for e in failed { print("error: ", e.message); }
    check::eq("challenges still served", site.started - site.ended, 0);
}

fn main() {
    let one = ["example.test"];
    let s = acme::Settings { directory: fake::DIRECTORY, domains: one, .. };
    {
        var site = fake::Site { .. };
        var ca = fake::ca(site);
        ca.authorized = true;
        ca.bad_nonces = 2;
        attempt("two nonces refused, then taken", ca, site, s);
    }
    {
        var site = fake::Site { .. };
        var ca = fake::ca(site);
        ca.authorized = true;
        ca.bad_nonces = 3;
        attempt("three nonces refused", ca, site, s);
    }
    {
        var site = fake::Site { .. };
        var ca = fake::ca(site);
        ca.fail_challenge = true;
        attempt("a challenge found invalid", ca, site, s);
    }
    {
        var site = fake::Site { .. };
        var ca = fake::ca(site);
        ca.refuse_order = true;
        attempt("an order refused", ca, site, s);
    }
    {
        var site = fake::Site { .. };
        var ca = fake::ca(site);
        attempt("no CA there", ca, site, acme::Settings { directory: "https://elsewhere.test/dir", domains: one, .. });
        attempt("no domains", ca, site, acme::Settings { directory: fake::DIRECTORY, .. });
    }
    {
        let dir = str(resource_dir(), "flow-failures-cache");
        var names: u8[>..] = [];
        if list_dir(dir, names) {
            each_split(names, '\n') { if it.len > 0 { delete_file(str(dir, "/", it)); } };
            delete_dir(dir);
        }
        let cached = acme::Settings { directory: fake::DIRECTORY, domains: one, cache: dir, .. };
        make_dir(dir);
        let path = acme::cache_path(dir, "cert", one, fake::DIRECTORY);
        write_file(path, "-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----\n");
        var site = fake::Site { .. };
        var ca = fake::ca(site);
        ca.authorized = true;
        let failed = acme::run() {
            let none, zero = acme::cached(cached);
            check::eq("a cached file that can't be read", none.len, 0);
        };
        check::eq("errors", failed.len, 0);
        attempt("ordered in its place", ca, site, cached);
        let failed2 = acme::run() {
            let pem, renew = acme::cached(cached);
            check::that("and cached", pem.len > 0);
        };
        check::eq("errors", failed2.len, 0);
    }
}
