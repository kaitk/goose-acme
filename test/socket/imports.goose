// A program that imports acme.socket and calls none of the calls that can
// fail compiles: scripts/test.sh checks it. Each such call is generic, so
// goose check doesn't take it as a root outside acme::run.
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import http from "github.com/kaitk/goose-http@5a780febed8e129d5bbf4c5278df117905e456ed";
import acme from "../../";
import acme.socket;

fn main() {
    let u, ok = http::parse_url(acme::LETS_ENCRYPT);
    print(u.host, " ", ok);
}
