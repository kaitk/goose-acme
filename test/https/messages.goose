// https URLs, the requests written, and responses read whole, in pieces, with
// a length, in chunks, up to the close, and malformed.
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import acme from "../../";
import check from "../";

fn url(u: const u8[:]) {
    let p, ok = acme::parse_url(u);
    if ok { print(u, " -> ", p.authority, " | ", p.host, " | ", p.port, " | ", p.path); }
    else { print(u, " -> not an https URL"); }
}

fn outcome(n: i64) -> const u8[:] {
    match n { acme::COMPLETE => "COMPLETE", acme::INCOMPLETE => "INCOMPLETE", _ => "MALFORMED" }
}

// Reads raw whole, then each prefix, which must be INCOMPLETE until the whole.
fn response(label: const u8[:], raw: const u8[:], closed: bool, head: bool) {
    var r = acme::Response { .. };
    var early = 0;
    for n in raw.len {
        if acme::read_response(raw[..n], false, head, r) == acme::COMPLETE { early++; }
    }
    let got = acme::read_response(raw, closed, head, r);
    print(label, ": ", outcome(got), " ", r.status, " location \"", r.location, "\" nonce \"", r.nonce,
          "\" retry ", r.retry_after, " body \"", r.body, "\"", if early > 0 { " (complete early): FAILED" } else { "" });
    assert(early == 0);
}

fn main() {
    url("https://acme-v02.api.letsencrypt.org/directory");
    url("https://localhost:14000/dir");
    url("https://[::1]:14000/dir?x=1");
    url("https://127.0.0.1");
    url("http://example.test/dir");
    url("https://:443/dir");
    url("https://example.test:0/");
    url("https://example.test:+443/");
    url("https://example.test:65536/");
    url("https://[::1/");
    url("https://user@example.test/");

    var req: u8[>..] = [];
    let p, ok = acme::parse_url("https://localhost:14000/order");
    acme::request(req, "POST", p, "{}");
    check::text("POST", req, "POST /order HTTP/1.1\r\nHost: localhost:14000\r\nUser-Agent: goose-acme\r\nAccept: */*\r\nConnection: close\r\nContent-Type: application/jose+json\r\nContent-Length: 2\r\n\r\n{}");
    req.clear();
    acme::request(req, "HEAD", p, "");
    check::text("HEAD", req, "HEAD /order HTTP/1.1\r\nHost: localhost:14000\r\nUser-Agent: goose-acme\r\nAccept: */*\r\nConnection: close\r\n\r\n");

    response("length", "HTTP/1.1 201 Created\r\nLocation: https://ca.test/acct/1\r\nreplay-NONCE:  abc \r\nContent-Length: 5\r\n\r\nhello", false, false);
    response("chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nRetry-After: 3\r\n\r\n3;x=y\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n", false, false);
    response("chunked, with a trailer", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n", false, false);
    response("to the close", "HTTP/1.1 200 OK\r\n\r\nhello", true, false);
    response("a HEAD", "HTTP/1.1 200 OK\r\nReplay-Nonce: n1\r\nContent-Length: 99\r\n\r\n", false, true);
    response("204", "HTTP/1.0 204 No Content\r\nReplay-Nonce: n2\r\n\r\n", false, false);
    response("cut at the close", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello", true, false);
    response("cut chunks", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", true, false);
    response("no status", "HTTP/1.1 OK\r\n\r\n", false, false);
    response("a bad length", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", false, false);
    response("a bad chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhello\r\n0\r\n\r\n", false, false);
    response("another coding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", false, false);
    response("a header without a colon", "HTTP/1.1 200 OK\r\nLocation\r\n\r\n", false, false);
}
