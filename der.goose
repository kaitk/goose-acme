// PEM, and the one thing read from inside a certificate: its validity, which
// sets when to renew it. goose-tls makes and signs what ACME sends; reading
// two dates needs no more of X.509 than the walk below.
namespace acme;

import std;
import base64;

let PRIVATE_KEY = "PRIVATE KEY";
let CERTIFICATE = "CERTIFICATE";

// The first PEM block in text from at with label: the bytes it encodes, and
// where in text the block ends, past its END line's line break; false when
// there is none, or its base64 is invalid.
fn pem_block(text: const u8[:], at: i64, label: const u8[:]) -> u8[>..], i64, bool {
    var der: u8[>..] = [];
    let begin = str("-----BEGIN ", label, "-----");
    let end = str("-----END ", label, "-----");
    let b = find(text[at..], begin);
    guard b >= 0 else { return der, 0, false; }
    let body_at = at + b + begin.len;
    let e = find(text[body_at..], end);
    guard e >= 0 else { return der, 0, false; }
    var b64: u8[>..] = [];
    for c in text[body_at..body_at + e] {
        if c != '\n' && c != '\r' && c != ' ' && c != '\t' { b64.push(c); }
    }
    var after = body_at + e + end.len;
    if after < text.len && text[after] == '\r' { after++; }
    if after < text.len && text[after] == '\n' { after++; }
    guard base64::decode(der, b64) else { return der, 0, false; }
    return der, after, true;
}

// der as a PEM block with label, its base64 in lines of 64.
fn pem(der: const u8[:], label: const u8[:]) -> u8[>..] {
    var b64: u8[>..] = [];
    base64::encode(b64, der);
    var out: u8[>..] = [];
    format(out, "-----BEGIN ", label, "-----\n");
    var at = 0;
    while at < b64.len {
        let n = min(64, b64.len - at);
        out.append(b64[at..at + n]);
        out.push('\n');
        at += n;
    }
    format(out, "-----END ", label, "-----\n");
    return out;
}

// A certificate file as the cache keeps it: the private key's PEM block first,
// then the chain, leaf first.
fn key_of(pem: const u8[:]) -> const u8[:] {
    let der, end, ok = pem_block(pem, 0, PRIVATE_KEY);
    return if ok { pem[..end] } else { pem[..0] };
}

fn chain_of(pem: const u8[:]) -> const u8[:] {
    let der, end, ok = pem_block(pem, 0, PRIVATE_KEY);
    guard ok else { return pem[..0]; }
    var at = end;
    while at < pem.len && (pem[at] == '\n' || pem[at] == '\r') { at++; }
    return pem[at..];
}

// The validity of the first certificate in pem, the leaf: not before and not
// after, in seconds since the epoch; false when pem holds no certificate DER
// reads.
fn validity(pem: const u8[:]) -> i64, i64, bool {
    let der, end, ok = pem_block(pem, 0, CERTIFICATE);
    guard ok else { return 0, 0, false; }
    // Certificate: SEQUENCE { tbsCertificate: SEQUENCE { [0] version
    // (optional), serialNumber, signature, issuer, validity, ... }, ... }.
    var at = 0;
    var tag, len, body = tlv(der, at);
    guard tag == 0x30 else { return 0, 0, false; }
    at = body;
    tag, len, body = tlv(der, at);
    guard tag == 0x30 else { return 0, 0, false; }
    at = body;
    tag, len, body = tlv(der, at);
    if tag == 0xA0 {
        at = body + len;
        tag, len, body = tlv(der, at);
    }
    for want in [0x02, 0x30, 0x30] {
        guard tag == want else { return 0, 0, false; }
        at = body + len;
        tag, len, body = tlv(der, at);
    }
    guard tag == 0x30 else { return 0, 0, false; }
    at = body;
    tag, len, body = tlv(der, at);
    let from, from_ok = der_time(der, tag, body, len);
    at = body + len;
    tag, len, body = tlv(der, at);
    let to, to_ok = der_time(der, tag, body, len);
    guard from_ok && to_ok else { return 0, 0, false; }
    return from, to, true;
}

// The DER element at at: its tag, its length, and where its contents start.
// Tag 0 when it doesn't fit in der or its length is malformed.
fn tlv(der: const u8[:], at: i64) -> i64, i64, i64 {
    guard at >= 0 && at + 2 <= der.len else { return 0, 0, 0; }
    let tag = der[at] as i64;
    var len = der[at + 1] as i64;
    var body = at + 2;
    if len >= 0x80 {
        let n = len - 0x80;
        guard n >= 1 && n <= 3 && body + n <= der.len else { return 0, 0, 0; }
        len = 0;
        for i in n { len = len << 8 | der[body + i]; }
        body += n;
    }
    guard body + len <= der.len else { return 0, 0, 0; }
    return tag, len, body;
}

// A UTCTime or GeneralizedTime in Zulu, as X.509 requires (RFC 5280, section
// 4.1.2.5), in seconds since the epoch.
fn der_time(der: const u8[:], tag: i64, at: i64, len: i64) -> i64, bool {
    let s = der[at..at + len];
    var year = 0;
    var rest = s;
    if tag == 0x17 && len == 13 {
        let yy, ok = digits(s[..2]);
        guard ok else { return 0, false; }
        year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        rest = s[2..];
    } else if tag == 0x18 && len == 15 {
        let yyyy, ok = digits(s[..4]);
        guard ok else { return 0, false; }
        year = yyyy;
        rest = s[4..];
    } else {
        return 0, false;
    }
    guard rest[10] == 'Z' else { return 0, false; }
    let month, m_ok = digits(rest[0..2]);
    let day, d_ok = digits(rest[2..4]);
    let hour, h_ok = digits(rest[4..6]);
    let minute, n_ok = digits(rest[6..8]);
    let second, s_ok = digits(rest[8..10]);
    guard m_ok && d_ok && h_ok && n_ok && s_ok && month >= 1 && month <= 12 && day >= 1 && day <= 31
          && hour < 24 && minute < 60 && second < 61 else { return 0, false; }
    return days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second, true;
}

fn digits(s: const u8[:]) -> i64, bool {
    var v = 0;
    for c in s {
        guard c >= '0' && c <= '9' else { return 0, false; }
        v = v * 10 + (c - '0');
    }
    return v, true;
}

// Days from 1970-01-01 to a date in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = div_euclid(y, 400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}
