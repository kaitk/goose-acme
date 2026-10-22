// base64url, the account key's JWK and its thumbprint, a key authorization's
// digest, and a signed request's protected header in both forms. The expected
// values were computed with Python's hashlib and base64.
import std;
import base64;
import json;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import acme from "../../";
import check from "../";

fn b64url(data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    acme::base64url(out, data);
    return out;
}

// The protected header of a flattened JWS, decoded.
fn header(jws: const u8[:]) -> u8[>..] {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, err = json::parse(jws, doc, decoded);
    let p, ok = json::as_string(json::member(root, "protected"));
    var t: u8[>..] = [];
    for b in p { t.push(if b == '-' { '+' } else if b == '_' { '/' } else { b }); }
    while t.len % 4 != 0 { t.push('='); }
    var out: u8[>..] = [];
    base64::decode(out, t);
    return out;
}

fn main() {
    // RFC 4648's vectors, and the two characters base64url changes.
    for pair in [["", ""], ["f", "Zg"], ["fo", "Zm8"], ["foo", "Zm9v"], ["foob", "Zm9vYg"],
                 ["fooba", "Zm9vYmE"], ["foobar", "Zm9vYmFy"], ["\xfb\xff", "-_8"], ["\xfb\xef\xbe", "----"]] {
        check::text(str("base64url \"", check::hex(pair[0]), "\""), b64url(pair[0]), pair[1]);
    }

    var xy: u8[>..] = [];
    for i in 64 { xy.push(i as u8); }
    let jwk = acme::jwk(xy);
    check::text("jwk", jwk, """{"crv":"P-256","kty":"EC","x":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","y":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"}""");
    check::text("thumbprint", acme::thumbprint(jwk), "0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0");
    check::text("key authorization digest", check::hex(acme::key_authorization_digest("tok", "thumb")),
                "b1803056ba83b553ae259bc01eead20183e812de5f155fc2e1b75238e5bea396");

    var key = tls::Key { .. };
    let failed = tls::run() { key = tls::key_generate(tls::P256); };
    check::eq("key errors", failed.len, 0);
    let errors = acme::run() {
        let first = acme::signed(key, jwk, "", "n1", "https://ca.test/account", "{}");
        check::text("with the key", header(first),
                    str("{\"alg\":\"ES256\",\"jwk\":", jwk, ",\"nonce\":\"n1\",\"url\":\"https://ca.test/account\"}"));
        let later = acme::signed(key, jwk, "https://ca.test/acct/1", "n\"2", "https://ca.test/order", "");
        check::text("with the account", header(later),
                    """{"alg":"ES256","kid":"https://ca.test/acct/1","nonce":"n\"2","url":"https://ca.test/order"}""");
        check::that("a POST-as-GET's empty payload", find(later, "\"payload\":\"\"") > 0);
    };
    check::eq("errors", errors.len, 0);
    tls::free(key);
}
