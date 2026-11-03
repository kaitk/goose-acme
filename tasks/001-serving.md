# 001: A server on the internet

Status: in-progress (2026-10-22). Waits on a public server.

The package gets certificates from Pebble through `acme.socket`, but two things in
goose-http stood between it and a goose-rest server facing Let's Encrypt (goose-rest's
task 049). Both are done:

- goose-http's `http.tls` took one context for every connection. Answering
  TLS-ALPN-01 needs `tls::choose_context`'s pause at the ClientHello, a connection that
  offers `acme-tls/1` moved to the challenge's context, and new connections moved to a
  renewed certificate's context while open ones keep theirs (goose-tls's task 003 has
  each of these calls). goose-http `v0.5.3` does this: `http::tls_server(ctx, chooser)`
  calls the program's `http::tls_hello(chooser, conn)` for each connection paused at
  its ClientHello, and goose-rest `v0.3.3`'s `rest.tls` takes that server
  (`http::TlsServerOf<C>&`).
- goose-http's blocking `connect` took `localhost` and IP addresses only, and Let's
  Encrypt's directory is a host name. Its task 053, step 4, resolved names in the
  blocking `connect` (`v0.5.2`), and the flow reached Let's Encrypt's staging service
  through it, up to an order for `example.com`, which it refused by policy
  (2026-10-22).

The program's glue is the module `acme.serve` (2026-11-03): a chooser per worker, fed
by mail from the lane that runs `acme::certificate`, with each challenge's context and
each certificate's. It needed goose-http `v0.5.17`, which gives `tls_hello` the
worker's chooser rather than a copy, so what it takes from mail lasts.
`test/live/serve.goose` gets two certificates from Pebble through it and renews them
while it serves. What remains is the run against Let's Encrypt's staging service from a
public server.

## Acceptance criteria

- [x] goose-http's `http.tls` chooses a context per connection, from a program's hook
      (goose-http `v0.5.3`)
- [x] A goose-http server gets a certificate from Pebble and renews it while it serves,
      without a restart (`acme.serve`, `test/live/serve.goose`, 2026-11-03; Plod's
      task 049 asked it of a goose-rest server)
- [x] `acme.socket` reaches a directory by name (Let's Encrypt's staging service,
      2026-10-22)
- [ ] A certificate from Let's Encrypt's staging service, for a public name, once a
      server answers its challenges
