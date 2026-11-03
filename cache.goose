// The cache: rustls-acme's DirCache layout, so a server that moves from
// rustls-acme keeps its account and certificates (docs/decisions.md). Each file
// is named after the SHA-256 of what it belongs to:
//
//   cached_account_<b64url(sha256(contact "\0" ... directory_url))>
//       the account key, PKCS#8 DER
//   cached_cert_<b64url(sha256(domain "\0" ... directory_url))>
//       the certificate's key as PKCS#8 PEM, a blank line, then the chain
//
// With Settings.autocert, the layout of Go's autocert.DirCache instead, as
// Thruster and other Go servers keep it:
//
//   acme_account+key
//       the account key, PEM: PKCS#8 as written, or SEC 1's EC PRIVATE KEY
//   <the first domain>
//       the certificate's key as PEM, then the chain, and nothing after it
//
// The directory is made 0700 and each file 0600, since they hold private
// keys (shim/mode.c); a file is written whole or not at all.
//
// The functions that fail have an untyped parameter, so that each is compiled
// only where a caller inside acme::run calls it (acme::fail).
namespace acme;

import std;
import os;
import hash from "github.com/kaitk/goose-hash@v0.0.4";

extern "ga_private" fn private_c(path: const u8[:], directory: bool) -> bool;

// The path of the file for kind, "account" or "cert", and items, the contacts
// or the domains, from directory_url, in dir.
fn cache_path(dir: const u8[:], kind: const u8[:], items: const u8[:][:], directory_url: const u8[:]) -> u8[>..] {
    var s = hash::Sha256 { .. };
    hash::sha256_reset(s);
    for item in items {
        hash::sha256_update(s, item);
        hash::sha256_update(s, "\x00");
    }
    hash::sha256_update(s, directory_url);
    var path: u8[>..] = [];
    path.append(dir);
    if dir.len > 0 && dir[dir.len - 1] != '/' { path.push('/'); }
    format(path, "cached_", kind, "_");
    base64url(path, hash::sha256_finish(s));
    return path;
}

// The account key's file for s, or "" without a cache.
fn account_path(s: Settings) -> u8[>..] {
    guard s.cache.len > 0 else { return []; }
    if s.autocert { return in_dir(s.cache, AUTOCERT_ACCOUNT); }
    return cache_path(s.cache, "account", s.contacts, s.directory);
}

// The certificate's file for s, or "" without a cache. autocert names it
// after the domain, so a name that isn't one fails.
fn cert_path(s) -> u8[>..] {
    guard s.cache.len > 0 && s.domains.len > 0 else { return []; }
    guard s.autocert else { return cache_path(s.cache, "cert", s.domains, s.directory); }
    let name = s.domains[0];
    guard name.len > 0 && name[0] != '.' && find(name, "/") < 0 && find(name, "\\") < 0 else {
        fail(str("not a file name for autocert's cache: ", name));
    }
    return in_dir(s.cache, name);
}

let AUTOCERT_ACCOUNT = "acme_account+key";

fn in_dir(dir: const u8[:], name: const u8[:]) -> u8[>..] {
    return str(dir, if dir[dir.len - 1] == '/' { "" } else { "/" }, name);
}

// The certificate file for key_pem and the CA's chain, as s's layout keeps
// it. autocert's reader takes nothing after the chain's last block.
fn cert_file(s: Settings, key_pem: const u8[:], chain: const u8[:]) -> u8[>..] {
    guard s.autocert else { return str(key_pem, "\n", chain); }
    var end = chain.len;
    while end > 0 && (chain[end - 1] == '\n' || chain[end - 1] == '\r' || chain[end - 1] == ' ') { end--; }
    return str(key_pem, chain[..end], "\n");
}

// Appends the file at path to out: true when it was there and read.
fn cache_load(path, out: u8[>..]&) -> bool {
    guard file_exists(path) else { return false; }
    guard read_file(path, out) else { fail(str("can't read ", path)); }
    return true;
}

// Writes data to path in dir, making dir first, and both private.
fn cache_store(dir, path: const u8[:], data: const u8[:]) {
    guard make_dir(dir) && private_c(dir, true) else { fail(str("can't make ", dir, " a private directory")); }
    guard write_file_atomic(path, data) && private_c(path, false) else { fail(str("can't write ", path)); }
}

// Makes dir, when it is set, and narrows its mode and its cached files'
// modes: a directory rustls-acme wrote has them as the umask left them.
fn cache_open(dir) {
    guard dir.len > 0 else { return; }
    guard make_dir(dir) && private_c(dir, true) else { fail(str("can't make ", dir, " a private directory")); }
    var names: u8[>..] = [];
    guard list_dir(dir, names) else { fail(str("can't list ", dir)); }
    each_split(names, '\n') { name =>
        if starts_with(name, "cached_") {
            let path = str(dir, if dir[dir.len - 1] == '/' { "" } else { "/" }, name);
            if file_exists(path) && !private_c(path, false) { fail(str("can't make ", path, " private")); }
        }
    };
}
