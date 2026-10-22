// HTTPS for ACME's requests: an https URL's parts, an HTTP/1.1 request, a
// response read from the bytes that come back, and https, which carries one
// exchange over goose-tls's client connection and a transport the caller
// supplies. Each exchange is a connection of its own, closed when it ends:
// ACME makes a dozen requests a certificate, months apart.
namespace acme;

import std;
import tls from "github.com/kaitk/goose-tls@v0.0.4";

// The largest response accepted: a certificate chain is a few kilobytes.
let MAX_RESPONSE = 1 << 20;

// An https URL's parts, as slices of it. authority is host[:port], as the
// Host header takes it; host has no brackets around an IPv6 address.
struct Url { authority: const u8[:], host: const u8[:], port: i64 = 443, path: const u8[:] }

// The parts of url, which must be https:// with a host, an optional port, and
// an optional path ("/" when absent); false for anything else.
fn parse_url(url: const u8[:]) -> Url, bool {
    guard starts_with(url, "https://") else { return Url { .. }, false; }
    let rest = url[8..];
    let stops = byte_set("/?#");
    var end = find_any(rest, stops);
    if end < 0 { end = rest.len; }
    var u = Url { authority: rest[..end], host: rest[..end], path: if end < rest.len { rest[end..] } else { "/" } };
    var port_at = -1;
    if u.authority.len > 0 && u.authority[0] == '[' {
        let close = find(u.authority, "]");
        guard close > 1 else { return Url { .. }, false; }
        u.host = u.authority[1..close];
        if close + 1 < u.authority.len {
            guard u.authority[close + 1] == ':' else { return Url { .. }, false; }
            port_at = close + 2;
        }
    } else {
        let colon = find(u.authority, ":");
        if colon >= 0 {
            u.host = u.authority[..colon];
            port_at = colon + 1;
        }
    }
    if port_at >= 0 {
        let port, ok = parse_int(u.authority[port_at..]);
        guard ok && port > 0 && port < 65536 && u.authority[port_at] != '+' else { return Url { .. }, false; }
        u.port = port;
    }
    let invalid = byte_set(" @\r\n");
    guard u.host.len > 0 && find_any(u.host, invalid) < 0 else { return Url { .. }, false; }
    if u.path[0] != '/' {
        return Url { .. }, false;
    }
    return u, true;
}

// Appends an HTTP/1.1 request for u to out: a GET, a HEAD, or a POST of body
// as JOSE, which every ACME request but the directory's and newNonce's is.
fn request(out: u8[>..]&, method: const u8[:], u: Url, body: const u8[:]) {
    format(out, method, " ", u.path, " HTTP/1.1\r\nHost: ", u.authority,
           "\r\nUser-Agent: goose-acme\r\nAccept: */*\r\nConnection: close\r\n");
    if method == "POST" {
        format(out, "Content-Type: application/jose+json\r\nContent-Length: ", body.len, "\r\n");
    }
    out.append("\r\n");
    if method == "POST" { out.append(body); }
}

// What read_response finds in the bytes so far.
let INCOMPLETE = 0;
let COMPLETE = 1;
let MALFORMED = -1;

// Reads an HTTP/1.1 response from raw into r: COMPLETE, INCOMPLETE when more
// bytes are needed, or MALFORMED. closed says the connection has ended, so a
// body with neither a length nor chunks ends with raw. A response to a HEAD
// has no body, whatever its headers say.
fn read_response(raw: const u8[:], closed: bool, head: bool, r: Response&) -> i64 {
    reset(r);
    let end = find(raw, "\r\n\r\n");
    guard end >= 0 else { return if closed || raw.len > 65536 { MALFORMED } else { INCOMPLETE }; }
    let lines = split(raw[..end], "\r\n");
    let status = lines[0];
    guard starts_with(status, "HTTP/1.") && status.len >= 12 && status[8] == ' ' else { return MALFORMED; }
    let code, ok = parse_int(status[9..12]);
    guard ok && code >= 100 else { return MALFORMED; }
    r.status = code;

    var length = -1;
    var chunked = false;
    for line in lines[1..] {
        let colon = find(line, ":");
        guard colon > 0 else { return MALFORMED; }
        let value = trim(line[colon + 1..]);
        var name: u8[..32] = [];
        guard colon <= 32 else { continue; }
        name.append(line[..colon]);
        to_lower(name);
        if name == "content-length" {
            let n, valid = parse_int(value);
            guard valid && n >= 0 && value[0] != '+' && value[0] != '-' else { return MALFORMED; }
            length = n;
        } else if name == "transfer-encoding" {
            var v: u8[..32] = [];
            guard value.len <= 32 else { return MALFORMED; }
            v.append(value);
            to_lower(v);
            guard v == "chunked" else { return MALFORMED; }
            chunked = true;
        } else if name == "location" {
            guard value.len <= 1024 else { return MALFORMED; }
            r.location.append(value);
        } else if name == "replay-nonce" {
            guard value.len <= 256 else { return MALFORMED; }
            r.nonce.append(value);
        } else if name == "retry-after" {
            let n, valid = parse_int(value);
            if valid && n > 0 { r.retry_after = n; }
        }
    }

    let body = raw[end + 4..];
    if head || r.status == 204 || r.status == 304 { return COMPLETE; }
    if chunked { return read_chunks(body, closed, r); }
    if length >= 0 {
        guard length <= MAX_RESPONSE else { return MALFORMED; }
        guard body.len >= length else { return if closed { MALFORMED } else { INCOMPLETE }; }
        r.body.append(body[..length]);
        return COMPLETE;
    }
    guard closed else { return if body.len > MAX_RESPONSE { MALFORMED } else { INCOMPLETE }; }
    guard body.len <= MAX_RESPONSE else { return MALFORMED; }
    r.body.append(body);
    return COMPLETE;
}

// A chunked body (RFC 9112, section 7.1) into r.body; trailers are ignored.
fn read_chunks(body: const u8[:], closed: bool, r: Response&) -> i64 {
    var at = 0;
    loop {
        let eol = find(body[at..], "\r\n");
        guard eol >= 0 else { return if closed { MALFORMED } else { INCOMPLETE }; }
        var size_text = body[at..at + eol];
        let semi = find(size_text, ";");
        if semi >= 0 { size_text = size_text[..semi]; }
        size_text = trim(size_text);
        guard size_text.len > 0 && size_text.len <= 8 else { return MALFORMED; }
        let size, ok = parse_int(size_text, 16);
        guard ok && size >= 0 && size_text[0] != '+' && size_text[0] != '-' else { return MALFORMED; }
        at += eol + 2;
        if size == 0 {
            let rest = body[at..];
            guard rest.len >= 2 else { return if closed { MALFORMED } else { INCOMPLETE }; }
            if rest[0] == '\r' && rest[1] == '\n' { return COMPLETE; }
            return if find(rest, "\r\n\r\n") >= 0 { COMPLETE } else if closed { MALFORMED } else { INCOMPLETE };
        }
        guard r.body.len + size <= MAX_RESPONSE else { return MALFORMED; }
        guard body.len - at >= size + 2 else { return if closed { MALFORMED } else { INCOMPLETE }; }
        guard body[at + size] == '\r' && body[at + size + 1] == '\n' else { return MALFORMED; }
        r.body.append(body[at..at + size]);
        at += size + 2;
    }
}

fn reset(r: Response&) {
    r.status = 0;
    r.location.clear();
    r.nonce.clear();
    r.retry_after = 0;
    r.body.clear();
}

// One HTTPS exchange: method on url with body, over a connection the
// transport t opens, with TLS from the client context ctx, its response into
// r. t is the caller's, through four overloads:
//
//   acme::open(t, host, port, why: u8[>..]&) -> bool   connects, or says why not
//   acme::send(t, bytes) -> bool                      sends all of bytes
//   acme::receive(t, buf: u8[:]) -> i64               bytes into buf; 0 at the end, < 0 failed
//   acme::hangup(t)                                   closes the connection
//
// Leaves through acme::fail when the connection or TLS fails or the response
// is malformed; the connection is closed either way.
fn https<T>(t: T&, ctx: tls::Context, method: const u8[:], url: const u8[:], body: const u8[:], r: Response&) {
    let u, ok = parse_url(url);
    guard ok else { fail(str("not an https URL: ", url)); }
    var why: u8[>..] = [];
    guard open(t, u.host, u.port, why) else { fail(str("can't connect to ", u.authority, ": ", why)); }
    let c = tls::connect(ctx, u.host);
    if !tls::ok(c) {
        hangup(t);
        fail(str("TLS to ", u.authority, ": ", tls::error_text()));
    }
    var req: u8[>..] = [];
    request(req, method, u, body);
    exchange_tls(t, c, req, method == "HEAD", r, why);
    tls::free(c);
    hangup(t);
    if why.len > 0 { fail(str(method, " ", url, ": ", why)); }
}

// Runs the handshake, sends req, and reads the response into r, or appends to
// why what went wrong.
fn exchange_tls<T>(t: T&, c: tls::Conn, req: const u8[:], head: bool, r: Response&, why: u8[>..]&) {
    var buf: u8[16384] = [0; 16384];
    var raw: u8[>..] = [];
    var sent = false;
    loop {
        var wants_input = true;
        if !sent {
            let h = tls::handshake(c);
            if h == 0 {
                guard tls::write(c, req) == req.len else { format(why, "TLS: ", tls::error_text()); return; }
                sent = true;
                wants_input = false;
            } else {
                guard h == tls::WANT_INPUT else { format(why, "TLS handshake: ", tls::error_text()); return; }
            }
        } else {
            let n = tls::read(c, buf);
            if n > 0 {
                guard raw.len + n <= MAX_RESPONSE + 65536 else { why.append("the response is too long"); return; }
                raw.append(buf[..n]);
                let got = read_response(raw, false, head, r);
                if got == COMPLETE { return; }
                guard got == INCOMPLETE else { why.append("a malformed HTTP response"); return; }
                wants_input = false;
            } else if n == tls::CLOSED {
                if read_response(raw, true, head, r) != COMPLETE { why.append("a malformed HTTP response"); }
                return;
            } else {
                guard n == tls::WANT_INPUT else { format(why, "TLS: ", tls::error_text()); return; }
            }
        }
        loop {
            let m = tls::drain(c, buf);
            guard m > 0 else { break; }
            guard send(t, buf[..m]) else { why.append("the connection failed while sending"); return; }
        }
        guard wants_input else { continue; }
        let got = receive(t, buf);
        // A response complete by its length or chunks has returned already. A
        // close without close_notify could cut one that ends at the close, so
        // only tls::CLOSED ends that kind.
        guard got > 0 else { why.append(if got == 0 { "the connection closed early" } else { "the connection failed" }); return; }
        guard tls::feed(c, buf[..got]) == got else { format(why, "TLS: ", tls::error_text()); return; }
    }
}
