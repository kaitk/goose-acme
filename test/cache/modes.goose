// The cache's file names, which match rustls-acme's DirCache (computed with
// Python's hashlib), and its modes: a directory made 0700, a file stored 0600,
// and a directory rustls-acme left with the umask's modes narrowed, but for
// files not its own.
import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import acme from "../../";
import check from "../";

extern "ga_mode" fn mode_c(path: const u8[:]) -> i64;

// 0700 and 0600: Goose has no octal literals.
let PRIVATE_DIR = 7 * 64;
let PRIVATE_FILE = 6 * 64;

fn mode(label: const u8[:], path: const u8[:], want: i64) {
    let m = mode_c(path);
    if m == want { print(label, ": ", format_mode(m)); }
    else { print(label, ": ", format_mode(m), ", expected ", format_mode(want), ": FAILED"); }
    assert(m == want);
}

fn format_mode(m: i64) -> u8[>..] {
    var out: u8[>..] = [];
    format_int(out, m, 8, 4, '0');
    return out;
}

fn clean(dir: const u8[:]) {
    var names: u8[>..] = [];
    if list_dir(dir, names) {
        each_split(names, '\n') { if it.len > 0 { delete_file(str(dir, "/", it)); } };
        delete_dir(dir);
    }
}

fn main() {
    let url = "https://acme.test/directory";
    let contacts = ["mailto:ops@snowtime.test"];
    let domains = ["snowtime.test"];
    let none: (const u8[:])[] = [];
    check::text("account", acme::cache_path("d", "account", contacts, url), "d/cached_account_IB1t1W6MWRcFv572Lp-Lw38YIZ1PWHyC-53thCXcLXk");
    check::text("cert", acme::cache_path("d/", "cert", domains, url), "d/cached_cert_BzbBWZl7k2hFR2PikTqCTN392jwwvHlLyatFgR0cBmo");
    check::text("no contacts", acme::cache_path("d", "account", none, acme::LETS_ENCRYPT),
                "d/cached_account_XnbTFRfs1mQOU8kW7TeI64kk-OHAL_EoQ84DHXSb9D4");

    let dir = str(resource_dir(), "cache-modes");
    clean(dir);
    let failed = acme::run() {
        acme::cache_open(dir);
        mode("a new directory", dir, PRIVATE_DIR);
        let path = acme::cache_path(dir, "cert", domains, url);
        acme::cache_store(dir, path, "cert");
        mode("a stored file", path, PRIVATE_FILE);
        var back: u8[>..] = [];
        check::that("read back", acme::cache_load(path, back) && back == "cert");
    };
    check::eq("errors", failed.len, 0);
    clean(dir);

    // As rustls-acme leaves it under a umask of 022.
    make_dir(dir);
    let theirs = str(dir, "/cached_account_x");
    let other = str(dir, "/notes.txt");
    write_file(theirs, "key");
    write_file(other, "text");
    let before = mode_c(other);
    let failed2 = acme::run() {
        acme::cache_open(dir);
        mode("an older directory", dir, PRIVATE_DIR);
        mode("an older cached file", theirs, PRIVATE_FILE);
        check::that("a file the cache didn't write, unchanged", before >= 0 && mode_c(other) == before);
    };
    check::eq("errors", failed2.len, 0);
    clean(dir);
}
