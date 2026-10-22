# 001: A server on the internet

Status: todo (2026-10-22). Waits on goose-http.

The package gets certificates from Pebble through `acme.socket`, but two things in
goose-http stand between it and a goose-rest server facing Let's Encrypt (goose-rest's
task 049):

- goose-http's `http.tls` takes one context for every connection. Answering
  TLS-ALPN-01 needs `tls::choose_context`'s pause at the ClientHello, a connection that
  offers `acme-tls/1` moved to the challenge's context, and new connections moved to a
  renewed certificate's context while open ones keep theirs (goose-tls's task 003 has
  each of these calls).
- goose-http's blocking `connect` takes `localhost` and IP addresses only, and Let's
  Encrypt's directory is a host name. Its task 053, step 4, resolves names in the
  blocking `connect`, where blocking is allowed.

## Acceptance criteria

- [ ] goose-http's `http.tls` chooses a context per connection, from a program's hook
- [ ] goose-rest's test server gets a certificate from Pebble and renews it while it
      serves, without a restart (goose-rest's task 049)
- [ ] `acme.socket` reaches a directory by name, and a certificate comes from Let's
      Encrypt's staging service
