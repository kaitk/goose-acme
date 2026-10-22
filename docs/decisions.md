# Decisions

Each decision is dated, with its reason and what it rejected. A change that contradicts
one records the new decision here, saying which it replaces, and updates
[architecture](architecture.md) in the same commit.

## Scope

- **A package of its own (2026-10-19).** ACME needs HTTPS requests and JSON, so it
  can't live in goose-tls, which goose-http's TLS depends on. Other Goose servers can use
  it without goose-http, and it moves with Let's Encrypt's API on its own schedule
  (goose-rest's task 049). It is named goose-acme, namespace `acme` (2026-10-22).
- **TLS-ALPN-01 only (2026-10-19).** The server answers the challenge on the port it
  already serves, 443, so no second listener or DNS provider is needed. Left out, as in
  rustls-acme's use in snowtime-native: HTTP-01, DNS-01, and wildcard certificates,
  which only DNS-01 can issue.

## The flow

- **No network I/O: a blocking flow over the program's values (2026-10-22).** The
  flow calls overloads on two values the program passes: `io` carries each HTTPS
  request and gives the time and the waits, and `challenges` serves each challenge
  certificate. Each call blocks, so the flow runs on a thread that may block, such as a
  goose-rest lane. This replaces task 049's proposal, a state that hands the program
  each request and takes its response. A certificate is renewed every two months, so
  nothing gains from interleaving its dozen requests with other work on a loop, and the
  state machine would carry every URL and nonce of the flow in fixed-size fields between
  steps. Trade-off: a program on an event loop runs the flow on another thread.
- **HTTPS in the package, over a byte transport (2026-10-22).** Replaced by the next
  decision. `acme::https` writes the HTTP/1.1 request, runs goose-tls's client
  connection, and reads the response, over four overloads that open, send, receive, and
  close a connection. A transport then needs no HTTP or TLS of its own; `acme.socket` is
  twenty lines over goose-http's blocking socket. Each request opens a connection and
  sends `Connection: close`. Rejected: keep-alive, which saves a handshake per request
  on a flow that runs every two months.
- **HTTPS is goose-http's `http.client` (2026-10-22).** This replaces HTTPS in the
  package. `acme.socket`'s `exchange` makes each request with goose-http's client,
  which writes it, runs goose-tls's client TLS, and reads the response, so goose-acme
  has no HTTP of its own, and its `acme::https`, the four transport overloads, and
  `https.goose` are gone. The client came from the same code, which goose-rest needed
  as well; one copy in goose-http now serves both. The core still does no network
  I/O: another server's program carries `exchange` with its own client. The session
  keeps its connection between requests, which the client does for every program;
  a flow that runs every two months gains little from it, and loses nothing. Rejected:
  keeping `acme::https` for a transport that isn't goose-http's, which no program
  uses.
- **Errors through `acme::run` and `acme::fail` (2026-10-22),** as goose-tls's and
  goose-sqlite's calls leave their `run`. The flow is a dozen requests deep, and each can
  fail. A function that calls `fail` has a generic parameter, so it is compiled only
  where a caller inside `run` calls it ([findings](goose-findings.md)).
- **A challenge is served only while its authorization is checked (2026-10-22).**
  `authorize` calls `challenge_end` after polling, whether the poll succeeded or not, by
  catching the failure with a nested `run` and failing again after. A failed flow leaves
  nothing for the program to clean up.
- **Retries (2026-10-22).** A `badNonce` answer is retried with the nonce it carries,
  up to three tries a request (RFC 8555, section 6.5). A status is polled up to 30 times,
  waiting the CA's `Retry-After`, capped at 60 seconds, or 2 seconds without one. A
  failed flow isn't retried: the program keeps serving what it has and calls again
  later, at a pace it chooses.
- **Fresh keys per order and per challenge (2026-10-22).** The certificate's key is new
  for each order and each challenge certificate's key new for each challenge, as
  rustls-acme does. The account key is made once and cached.

## The cache

- **rustls-acme's layout is the cache's only format (2026-10-22).** File names hash
  the contacts or domains with the directory URL, the account file holds the key as
  PKCS#8 DER, and the certificate file holds the key's PEM, a blank line, and the chain.
  A server that moves from rustls-acme, as snowtime-native's edge would, keeps its
  account and certificates with no setting, and the directory URL in the name keeps
  staging and production apart. Rejected: a format of the package's own with an option
  to read rustls-acme's, which needs a second format and a flag for no gain.
- **Renewal two thirds into the validity (2026-10-22),** as rustls-acme renews: day 60
  of a 90-day certificate, and day 4 of Let's Encrypt's 6-day ones.
- **The certificate's dates from a DER walk (2026-10-22).** `acme::validity` reads the
  leaf's `notBefore` and `notAfter` with a walk of five DER elements. goose-tls has no
  call for them, and adding one would change goose-tls while its task 007 rewrites the
  server. Rejected: renewing from the time of issue, which a cached certificate from
  rustls-acme doesn't record.
- **File modes in C, for now (2026-10-22).** Goose's `os` module can't set a mode, so
  `shim/mode.c` makes the directory 0700 and each file 0600 with `chmod`. This replaces
  "Goose with no C" for that purpose only, until `os` can set a mode
  ([findings](goose-findings.md)). On Windows the shim does nothing, and the directory's
  ACL is the operator's. The files are written with `write_file_atomic`, so a crash
  leaves the old file or the new one.
