# Architecture

How goose-acme works, for a program that uses it. The reasons are in
[decisions](decisions.md).

## The flow

`acme::certificate(io, challenges, settings)` returns a certificate for
`settings.domains` and the time to renew it, in seconds since the epoch. When the
cache holds one before its renewal time, it returns that and makes no request.
Otherwise it orders one from `settings.directory` (RFC 8555, section 7):

1. `GET` the directory, then `HEAD` its `newNonce` for the first nonce.
2. Load the account key from the cache, or make a P-256 key and cache it. `POST`
   `newAccount` with it, which creates the account or finds the existing one; its URL
   signs every later request. With `settings.eab_kid` and `eab_key`, the payload binds
   the account to the CA's (RFC 8555, section 7.3.4): a JWS of the account's JWK with
   `HS256` under the key, which is base64url, as the CA gives it.
3. `POST` `newOrder` with the domains.
4. For each authorization that isn't valid yet: make a TLS-ALPN-01 challenge
   certificate (RFC 8737) for the key authorization's SHA-256, call
   `challenge_start`, `POST` the challenge, poll the authorization until it isn't
   `pending`, and call `challenge_end`.
5. Poll the order until it is `ready`, make the certificate's key and a CSR, `POST`
   `finalize`, and poll until the order is `valid`.
6. `POST`-as-`GET` the certificate. The result is the key's PEM, a blank line, and the
   chain, which the cache stores; in autocert's layout, no blank line, and nothing
   after the chain.

Every request but the first two is a JWS signed with ES256 by goose-tls, with the
account key as a JWK in `newAccount` and the account URL after.

## The program's values

The flow calls these overloads, which the program defines for its own types, or takes
from `acme.socket`:

| Call | Does |
|---|---|
| `acme::exchange(io, method, url, body, r: acme::Response&)` | One HTTPS request: `GET`, `HEAD`, or a `POST` of `body` as `application/jose+json`. Fills `r` with the status, `Location`, `Replay-Nonce`, `Retry-After`, and the body, or leaves through `acme::fail` |
| `acme::wait(io, seconds)` | Before polling a status again |
| `acme::now(io) -> i64` | Seconds since the epoch |
| `acme::challenge_start(challenges, name, certificate_pem, key_pem)` | Answer a TLS handshake for `name` that offers ALPN `acme-tls/1` with this certificate, until `challenge_end` |
| `acme::challenge_end(challenges, name)` | Stop answering for `name` |

Both values are passed by reference, so overloads can keep state in them. An overload
that calls `acme::fail` needs a parameter without a type, as `acme.socket`'s
`exchange` has, or a program that never calls `acme::certificate` doesn't build
([findings](goose-findings.md)).

A server on goose-tls answers the challenge with `tls::choose_context`: at the
`HELLO` pause, a connection that offers `acme-tls/1` for a name being challenged moves
to a context made from the challenge's certificate and key (goose-tls's
[architecture](https://github.com/kaitk/goose-tls/blob/main/docs/architecture.md#a-context-per-connection)).

## HTTPS through acme.socket

The module `acme.socket` defines all of `io`'s calls on `acme::Socket`, which holds a
session of goose-http's `http.client`
([its API](https://github.com/kaitk/goose-http/blob/main/docs/api.md#an-http-client)),
each wait limited to the milliseconds given: `acme::socket(ms)` trusts OpenSSL's store
of certificate authorities, and `acme::socket(ca, ms)` only `ca`'s certificates, for a
test CA. Its `exchange` sends a GET, a HEAD, or a POST of the body as
`application/jose+json`, and fills the `acme::Response` with the status, `Location`,
`Replay-Nonce`, `Retry-After` in seconds, and the body, up to 1 MB. The session keeps
its connection to the CA between requests. A response to a HEAD has no body, and one
cut by a close without TLS's `close_notify` fails, as the client reads them. A failed
request leaves `run` with the step and the reason in words, such as
`connect ECONNREFUSED` or `resolve ENOENT (no such name)`. goose-http's `connect`
resolves a directory's host name, such as Let's Encrypt's, with the system's resolver;
the time limit doesn't bound the lookup.

A program whose server isn't goose-http defines `exchange`, `wait`, and `now` on a
value of its own, over its own HTTPS client.

## The cache

`settings.cache` names a directory, or is empty for none. The files follow
rustls-acme's `DirCache`:

| File | Holds |
|---|---|
| `cached_account_<h>`, `h` = base64url(SHA-256(each contact, `\0`, then the directory URL)) | The account key, PKCS#8 DER |
| `cached_cert_<h>`, `h` = the same over the domains | The certificate's key as PKCS#8 PEM, a blank line, then the chain, leaf first |

With `settings.autocert`, they follow Go's `autocert.DirCache`, as Thruster keeps it:

| File | Holds |
|---|---|
| `acme_account+key` | The account key as PEM: PKCS#8 as the flow writes it, or SEC 1's `EC PRIVATE KEY` as autocert does |
| the first domain, such as `example.com` | The certificate's key as PEM, either kind, then the chain, leaf first, and nothing after it |

A domain that isn't a file name, one with a `/` or starting with `.`, fails.

The flow makes the directory 0700 and each file 0600, and narrows a directory
rustls-acme left with wider modes, touching only files named `cached_*`. It writes each
file with `write_file_atomic`, which can leave a `.tmp` file after a crash.

`acme::cached(settings)` returns the cached certificate and its renewal time without a
request, or empty when there is none or it can't be read: for a program to serve at
startup while it orders a new one. `acme::key_of(pem)` and `acme::chain_of(pem)` split
the file for `tls::server`, and `acme::validity(pem)` reads the first certificate's
dates.

## A program's loop

```goose
var renew_at = 0;
acme::run() {
    let pem, at = acme::cached(s);
    if pem.len > 0 { serve(acme::chain_of(pem), acme::key_of(pem)); renew_at = at; }
};
loop {
    if time() as i64 >= renew_at {
        let failed = acme::run() {
            var io = acme::socket(10000);
            let pem, at = acme::certificate(io, challenges, s);
            acme::free(io);
            serve(acme::chain_of(pem), acme::key_of(pem));   // new connections take it
            renew_at = at;
        };
        if failed.len > 0 { renew_at = time() as i64 + 3600; }   // keep serving; try again
    }
    sleep_ms(60000);
}
```

The renewal time is two thirds into the certificate's validity, so a failure leaves a
third of it, 30 days of a 90-day certificate, for retries.

## A goose-http server: acme.serve

The module `acme.serve` is that loop for a goose-http server, on a lane of its own,
with each worker's TLS choosing its context at the ClientHello
([decisions](decisions.md#serving-acmeserve)):

```goose
thread_fn worker(cfg: http::Config, service: acme::Service) {
    var server = acme::tls_server(service);
    http::exit_on_error(http::serve_epoll(cfg, fresh, server) { ev, st, out => ... });
    acme::release(server);
}

var plan = acme::Plan { workers: 4, .. };
plan.directory.append(acme::LETS_ENCRYPT);
plan.cache.append("/var/lib/app/acme");
acme::plan_certificate(plan, ["example.com"]);
acme::plan_certificate(plan, ["www.example.com"]);
let service, err = acme::serve(plan);
var cfg = http::Config { port: 443, tls: true, workers: 4, .. };
http::run(cfg, service, worker);
```

| Call | Does |
|---|---|
| `Plan { directory, contacts, certificates, cache, autocert, eab_kid, eab_key, ca, protocols, workers }` | `Settings` as flat text, for the lane's thread: contacts one a line; `certificates` one a line, its names separated by spaces; `ca`, PEM, trusted for the directory in place of OpenSSL's store; `protocols`, ALPN names separated by commas, `h2,http/1.1` when empty; `workers`, how many to wait for |
| `plan_certificate(p, names)` | Adds a line for one certificate for `names`, lowercased |
| `serve(p) -> Service, error` | Makes the context every connection is accepted from, and starts the lane; `error` is empty, or why it can't |
| `tls_server(service)` | In a worker, before its loop: an `http::TlsServerOf<acme::Chooser>` whose chooser joins the lane |
| `release(server)` | Frees it once the loop has returned |
| `stop(service)` | Stops the lane once the workers have returned |

The lane serves each cached certificate that hasn't expired at once, then orders each
one that is due, its renewal time past or none cached, and sleeps until the next. It
logs each certificate it serves, and each failure, to stderr. For each order it mails
every worker the challenge's context while the CA checks it, and then the
certificate's; a worker that joins later gets every certificate held. A connection
moves to the context for its SNI name, lowercased and without a final dot: a challenge
while one lasts for a client that offers `acme-tls/1`, the certificate otherwise. One
whose name has neither stays on the placeholder context, which offers only
`acme-tls/1`, so a client that asks for h2 or HTTP/1.1 is refused.
