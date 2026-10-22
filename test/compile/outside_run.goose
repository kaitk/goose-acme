// acme::certificate, which can fail, outside acme::run doesn't compile.
import std;
import hash from "github.com/kaitk/goose-hash@v0.0.4";
import tls from "github.com/kaitk/goose-tls@v0.0.5";
import acme from "../../";
import fake from "../";

fn main() {
    var site = fake::Site { .. };
    var ca = fake::ca(site);
    let one = ["example.test"];
    let pem, renew = acme::certificate(ca, site, acme::Settings { directory: fake::DIRECTORY, domains: one, .. });
}
// error: return from run: no enclosing call of run on this compile-time call path
