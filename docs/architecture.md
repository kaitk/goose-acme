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
   signs every later request.
3. `POST` `newOrder` with the domains.
4. For each authorization that isn't valid yet: make a TLS-ALPN-01 challenge
   certificate (RFC 8737) for the key authorization's SHA-256, call
   `challenge_start`, `POST` the challenge, poll the authorization until it isn't
   `pending`, and call `challenge_end`.
5. Poll the order until it is `ready`, make the certificate's key and a CSR, `POST`
   `finalize`, and poll until the order is `valid`.
6. `POST`-as-`GET` the certificate. The result is the key's PEM, a blank line, and the
   chain, which the cache stores.

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

Both values are passed by reference, so overloads can keep state in them.

A server on goose-tls answers the challenge with `tls::choose_context`: at the
`HELLO` pause, a connection that offers `acme-tls/1` for a name being challenged moves
to a context made from the challenge's certificate and key (goose-tls's
[architecture](https://github.com/kaitk/goose-tls/blob/main/docs/architecture.md#a-context-per-connection)).

## HTTPS over a transport

`acme::https(t, ctx, method, url, body, r)` is an `exchange` for any transport: it
parses the `https` URL, opens a connection, runs goose-tls's client handshake with
`ctx`, sends the HTTP/1.1 request with `Connection: close`, and reads the response,
which may have a `Content-Length`, chunks, or end at the TLS close. A response cut by a
close without `close_notify` fails. The transport `t` supplies:

| Call | Does |
|---|---|
| `acme::open(t, host, port, why: u8[>..]&) -> bool` | Connects, or appends why not |
| `acme::send(t, bytes) -> bool` | Sends all of `bytes` |
| `acme::receive(t, buf) -> i64` | Bytes into `buf`; 0 at the end, below 0 on failure |
| `acme::hangup(t)` | Closes the connection |

The module `acme.socket` defines all of `io`'s calls on `acme::Socket`, over
goose-http's blocking socket, each wait limited to the milliseconds given:
`acme::socket(ms)` trusts OpenSSL's store of certificate authorities, and
`acme::socket(ca, ms)` only `ca`'s certificates, for a test CA. goose-http's `connect`
takes `localhost` or an IP address, so a directory named by a host name, such as Let's
Encrypt's, can't be reached through it yet.

## The cache

`settings.cache` names a directory, or is empty for none. The files follow
rustls-acme's `DirCache`:

| File | Holds |
|---|---|
| `cached_account_<h>`, `h` = base64url(SHA-256(each contact, `\0`, then the directory URL)) | The account key, PKCS#8 DER |
| `cached_cert_<h>`, `h` = the same over the domains | The certificate's key as PKCS#8 PEM, a blank line, then the chain, leaf first |

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
