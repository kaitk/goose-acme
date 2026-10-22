#!/usr/bin/env python3
"""Answers TLS-ALPN-01 for scripts/pebble.sh: a TLS server on 127.0.0.1:PORT
that, for a client offering acme-tls/1 and naming NAME in SNI, presents
DIR/NAME.crt with DIR/NAME.key, as test/live/pebble.goose writes them while a
challenge is live. A name with no files fails the handshake, as Pebble expects
of a challenge nobody answers.

    scripts/challenge.py DIR PORT
"""

import os
import socket
import ssl
import sys
import threading


def main():
    folder, port = sys.argv[1], int(sys.argv[2])

    def context_for(name):
        crt, key = os.path.join(folder, name + ".crt"), os.path.join(folder, name + ".key")
        if not (os.path.exists(crt) and os.path.exists(key)):
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["acme-tls/1"])
        ctx.load_cert_chain(crt, key)
        return ctx

    def choose(conn, name, ctx):
        chosen = context_for(name or "")
        if chosen is None:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        conn.context = chosen
        return None

    base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    base.set_alpn_protocols(["acme-tls/1"])
    base.sni_callback = choose

    listener = socket.create_server(("127.0.0.1", port), reuse_port=False)
    print(f"challenge.py: serving {folder} on 127.0.0.1:{port}", flush=True)

    def serve(conn):
        try:
            with base.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError):
            pass

    while True:
        conn, _ = listener.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
