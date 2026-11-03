// JWS as ACME uses it (RFC 8555, section 6.2): ES256 over the account's P-256
// key, in the flattened JSON form, with the key as a JWK until the account has
// a URL and the URL after.
namespace acme;

import std;
import base64;
import json;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.6";

// Appends data in base64url without padding (RFC 7515, section 2).
fn base64url(out: u8[>..]&, data: const u8[:]) {
    let at = out.len;
    base64::encode(out, data);
    while out.len > at && out[out.len - 1] == '=' { out.pop(); }
    for &c in out[at..] {
        if c == '+' { c = '-'; } else if c == '/' { c = '_'; }
    }
}

// The bytes base64url text encodes, padded or not; false when it isn't
// base64url.
fn unbase64url(text: const u8[:]) -> u8[>..], bool {
    var b64: u8[>..] = [];
    for c in text {
        if c == '-' { b64.push('+'); } else if c == '_' { b64.push('/'); } else if c == '+' || c == '/' { return [], false; } else { b64.push(c); }
    }
    while b64.len % 4 != 0 { b64.push('='); }
    var out: u8[>..] = [];
    let ok = base64::decode(out, b64);
    return out, ok;
}

// The externalAccountBinding member of newAccount's payload (RFC 8555,
// section 7.3.4): a JWS of the account's JWK, for url, with the CA's key
// identifier kid, MACed with HS256 under hmac_key.
fn external_account_binding(hmac_key: const u8[:], kid: const u8[:], url: const u8[:], jwk: const u8[:]) -> u8[>..] {
    var protected: u8[>..] = [];
    protected.append("{\"alg\":\"HS256\",");
    json::format_key(protected, "kid");
    json::format_string(protected, kid);
    protected.push(',');
    json::format_key(protected, "url");
    json::format_string(protected, url);
    protected.push('}');
    var input: u8[>..] = [];
    base64url(input, protected);
    input.push('.');
    base64url(input, jwk);
    let dot = find(input, ".");
    var out: u8[>..] = [];
    out.append("{\"protected\":\"");
    out.append(input[..dot]);
    out.append("\",\"payload\":\"");
    out.append(input[dot + 1..]);
    out.append("\",\"signature\":\"");
    base64url(out, hash::hmac_sha256(hmac_key, input));
    out.append("\"}");
    return out;
}

// The account key's public JWK (RFC 7518, section 6.2.1), with its members in
// the order and spacing RFC 7638's thumbprint hashes.
fn jwk(xy: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
    base64url(out, xy[..32]);
    out.append("\",\"y\":\"");
    base64url(out, xy[32..64]);
    out.append("\"}");
    return out;
}

// The JWK's thumbprint (RFC 7638) in base64url: what a key authorization ends
// with.
fn thumbprint(jwk: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    base64url(out, hash::sha256(jwk));
    return out;
}

// TLS-ALPN-01's digest of a key authorization, token "." thumbprint (RFC 8555,
// section 8.1), which the challenge certificate carries.
fn key_authorization_digest(token: const u8[:], thumbprint: const u8[:]) -> u8[32] {
    var ka: u8[>..] = [];
    format(ka, token, ".", thumbprint);
    return hash::sha256(ka);
}

// The flattened JWS of payload for url, signed with key: with jwk in its
// protected header when kid is "", with kid otherwise. payload "" is a
// POST-as-GET. Fails through acme::fail when the key can't sign.
fn signed(key, jwk: const u8[:], kid: const u8[:], nonce: const u8[:], url: const u8[:],
          payload: const u8[:]) -> u8[>..] {
    var protected: u8[>..] = [];
    protected.append("{\"alg\":\"ES256\",");
    if kid.len == 0 {
        json::format_key(protected, "jwk");
        protected.append(jwk);
    } else {
        json::format_key(protected, "kid");
        json::format_string(protected, kid);
    }
    protected.push(',');
    json::format_key(protected, "nonce");
    json::format_string(protected, nonce);
    protected.push(',');
    json::format_key(protected, "url");
    json::format_string(protected, url);
    protected.push('}');

    var input: u8[>..] = [];
    base64url(input, protected);
    input.push('.');
    base64url(input, payload);
    var signature: u8[>..] = [];
    let failed = tls::run() { signature.append(tls::sign_es256(key, input)); };
    for e in failed { fail(str("signing a request: ", e.message)); }

    let dot = find(input, ".");
    var out: u8[>..] = [];
    out.append("{\"protected\":\"");
    out.append(input[..dot]);
    out.append("\",\"payload\":\"");
    out.append(input[dot + 1..]);
    out.append("\",\"signature\":\"");
    base64url(out, signature);
    out.append("\"}");
    return out;
}
