// A certificate's validity, in UTCTime (test/data/utc.pem) and in
// GeneralizedTime (test/data/generalized.pem), made with openssl req -x509
// -not_before and -not_after and checked against Python's calendar.timegm;
// PEM in and out; and a cached certificate file split into key and chain.
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.4";
import acme from "../../";
import check from "../";

fn dates(label: const u8[:], pem: const u8[:], from: i64, to: i64) {
    let f, t, ok = acme::validity(pem);
    check::that(str(label, " read"), ok);
    check::eq(str(label, " not before"), f, from);
    check::eq(str(label, " not after"), t, to);
}

fn main() {
    let utc = embed_file("../data/utc.pem");
    let generalized = embed_file("../data/generalized.pem");
    dates("UTCTime 2000-02-29T12:00:00Z to 2049-12-31T23:59:59Z", utc, 951825600, 2524607999);
    dates("GeneralizedTime 2050-01-01T00:00:00Z to 2107-12-06T19:42:10Z", generalized, 2524608000, 4352643730);
    check::eq("1970-01-01", acme::days_from_civil(1970, 1, 1), 0);
    check::eq("1600-03-01", acme::days_from_civil(1600, 3, 1), -135080);

    let f, t, ok = acme::validity("no certificate");
    check::that("no certificate", !ok);
    let cut = str("-----BEGIN CERTIFICATE-----\n", utc[28..90], "\n-----END CERTIFICATE-----\n");
    let f2, t2, ok2 = acme::validity(cut);
    check::that("a cut certificate", !ok2);

    let der, end, found = acme::pem_block(utc, 0, acme::CERTIFICATE);
    check::that("the block found, to its end", found && end == utc.len);
    check::that("and written back the same", acme::pem(der, acme::CERTIFICATE) == utc);

    let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    let file = str(key, "\n", utc, generalized);
    check::that("key_of", acme::key_of(file) == key);
    check::that("chain_of", acme::chain_of(file) == str(utc, generalized));
    check::that("no key", acme::key_of(utc).len == 0 && acme::chain_of(utc).len == 0);
}
