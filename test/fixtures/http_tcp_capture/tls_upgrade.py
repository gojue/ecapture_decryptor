#!/usr/bin/env python3
"""Independent plaintext-to-TLS and HTTPS CONNECT loopback peers.

Start tcpdump/dumpcap on TCP ports 44446-44453 before running this program.
Only Python's standard library is required; no SDK or capture writer is used.
Each mode opens a refused connection and a separate successful connection.
The post-upgrade HTTP payload tests TLS handoff, not mail/database semantics.
"""
# Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
# See LICENSE for the applicable license.

import argparse
import hashlib
import json
import os
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor


PORTS = dict(smtp=44446, imap=44447, pop3=44448, ldap=44449,
             postgres=44450, mysql=44451, connect=44452, https_connect=44453)
FAKE_TLS = b"\x16\x03\x03\x00\x10not-a-TLS-record"


def read_exact(peer, expected):
    data = bytearray()
    while len(data) < len(expected):
        fragment = peer.recv(len(expected) - len(data))
        assert fragment, "peer closed before completing expected bytes"
        data.extend(fragment)
    assert bytes(data) == expected, "peer bytes differ from expected transcript"


def write_fragments(peer, data):
    # Separate writes cross line endings, binary lengths and application bodies.
    for part in (data[:1], data[1:3], data[3:]):
        if part:
            peer.sendall(part)
            time.sleep(.002)


class TLSStream:
    """SSLObject over either a real socket or another TLSStream."""

    def __init__(self, peer, context, server, prefix=b""):
        self.peer = peer
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.ssl = context.wrap_bio(self.incoming, self.outgoing,
                                    server_side=server,
                                    server_hostname=None if server else "localhost")
        self.prefix = prefix

    def flush(self):
        data = self.outgoing.read()
        if data:
            self.peer.sendall(self.prefix + data)
            self.prefix = b""

    def receive(self):
        self.flush()
        data = self.peer.recv(65536)
        if data:
            self.incoming.write(data)
        else:
            self.incoming.write_eof()

    def handshake(self):
        while True:
            try:
                self.ssl.do_handshake()
                self.flush()
                assert self.ssl.version() == "TLSv1.3"
                assert self.ssl.selected_alpn_protocol() == "http/1.1"
                return self
            except ssl.SSLWantReadError:
                self.receive()
            except ssl.SSLWantWriteError:
                self.flush()

    def sendall(self, data):
        while data:
            try:
                written = self.ssl.write(data)
                data = data[written:]
                self.flush()
            except ssl.SSLWantReadError:
                self.receive()
            except ssl.SSLWantWriteError:
                self.flush()

    def recv(self, length):
        while True:
            try:
                data = self.ssl.read(length)
                self.flush()
                return data
            except ssl.SSLWantReadError:
                self.receive()
            except ssl.SSLZeroReturnError:
                return b""

    def close_notify(self):
        while True:
            try:
                self.ssl.unwrap()
                self.flush()
                return
            except ssl.SSLWantReadError:
                self.receive()
            except ssl.SSLWantWriteError:
                self.flush()


def contexts(args, keylog):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(args.cert, args.key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE  # Ephemeral isolated loopback peers only.
    client.keylog_filename = keylog
    for context in (client, server):
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
    return client, server


def ber(tag, value):
    assert len(value) < 128
    return bytes((tag, len(value))) + value


def ldap_request():
    return ber(0x30, ber(0x02, b"\x01") + ber(0x77, ber(0x80, b"1.3.6.1.4.1.1466.20037")))


def ldap_response(accepted):
    result = ber(0x0a, b"\x00" if accepted else b"\x34") + ber(0x04, b"")
    result += ber(0x04, b"" if accepted else b"temporarily unavailable")
    return ber(0x30, ber(0x02, b"\x01") + ber(0x78, result))


def mysql_packet(sequence, body):
    return struct.pack("<I", len(body))[:3] + bytes((sequence,)) + body


def mysql_greeting(accepted):
    flags = 0x200 | 0x8000 | 0x80000 | (0x800 if accepted else 0)
    body = b"\x0a8.0-fixture\x00" + struct.pack("<I", 123) + b"12345678\x00"
    body += struct.pack("<HBHHB", flags & 0xffff, 45, 2, flags >> 16, 21)
    body += bytes(10) + b"abcdefghijkl\x00mysql_native_password\x00"
    return mysql_packet(0, body)


def mysql_ssl_request():
    body = struct.pack("<IIB", 0x200 | 0x800 | 0x8000 | 0x80000, 1 << 24, 45) + bytes(23)
    return mysql_packet(1, body)


def prelude(mode, accepted):
    if mode == "smtp":
        return [("S", b"220 fixture ESMTP ready\r\n"), ("C", b"EHLO localhost\r\n"),
                ("S", b"250-fixture\r\n250-STARTTLS\r\n250 OK\r\n"), ("C", b"STARTTLS\r\n"),
                ("S", b"220 Begin TLS\r\n" if accepted else b"454 TLS unavailable\r\n")]
    if mode == "imap":
        return [("S", b"* OK fixture IMAP ready\r\n"), ("C", b"a1 CAPABILITY\r\n"),
                ("S", b"* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK completed\r\n"),
                ("C", b"a2 STARTTLS\r\n"),
                ("S", b"a2 OK Begin TLS\r\n" if accepted else b"a2 NO TLS unavailable\r\n")]
    if mode == "pop3":
        return [("S", b"+OK fixture POP3 ready\r\n"), ("C", b"CAPA\r\n"),
                ("S", b"+OK capabilities\r\nSTLS\r\n.\r\n"), ("C", b"STLS\r\n"),
                ("S", b"+OK Begin TLS\r\n" if accepted else b"-ERR TLS unavailable\r\n")]
    if mode == "ldap":
        return [("C", ldap_request()), ("S", ldap_response(accepted))]
    if mode == "postgres":
        return [("C", struct.pack("!II", 8, 80877103)), ("S", b"S" if accepted else b"N")]
    if mode == "mysql":
        return [("S", mysql_greeting(accepted))]
    assert mode in ("connect", "https_connect")
    return [("C", b"CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\r\n"),
            ("S", b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: fixture\r\n\r\n" if accepted else
             b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=fixture\r\nContent-Length: 0\r\n\r\n")]


def http_messages(mode):
    request_body = b"d09/" + mode.encode() + b"/request\x00\r\n\xff"
    response_body = b"d09/" + mode.encode() + b"/response\x00\r\n\xff"
    request = (f"POST /d09/{mode} HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/octet-stream\r\n"
               f"Content-Length: {len(request_body)}\r\n\r\n").encode() + request_body
    response = ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                f"Content-Length: {len(response_body)}\r\n\r\n").encode() + response_body
    return request, response


def run_exchange(args, mode, accepted):
    client_context, server_context = contexts(args, args.keylog)
    inner_client, inner_server = contexts(args, args.inner_keylog) if mode == "https_connect" else (None, None)

    def peer(raw, server):
        raw.settimeout(10)
        stream = raw
        outer = None
        if mode == "https_connect":
            outer = TLSStream(raw, server_context if server else client_context, server).handshake()
            stream = outer
        for direction, data in prelude(mode, accepted):
            if (direction == "S") == server:
                write_fragments(stream, data)
            else:
                read_exact(stream, data)
        if not accepted:
            # A rejected negotiation must never turn these plaintext bytes into TLS.
            client_data = FAKE_TLS + b"/" + mode.encode() + b"\r\n"
            server_data = b"plain-rejected/" + mode.encode() + b"\r\n"
            if server:
                read_exact(stream, client_data)
                write_fragments(stream, server_data)
            else:
                write_fragments(stream, client_data)
                read_exact(stream, server_data)
        else:
            prefix = b""
            if mode == "mysql":
                request = mysql_ssl_request()
                if server:
                    read_exact(stream, request)
                else:
                    stream.sendall(request[:3])
                    time.sleep(.002)
                    # The SSLRequest tail and actual ClientHello share one write.
                    prefix = request[3:]
            context = (inner_server if server else inner_client) if outer else (server_context if server else client_context)
            tls = TLSStream(stream, context, server, prefix).handshake()
            request, response = http_messages(mode)
            if server:
                read_exact(tls, request)
                write_fragments(tls, response)
            else:
                write_fragments(tls, request)
                read_exact(tls, response)
            tls.close_notify()
        if outer:
            outer.close_notify()

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", PORTS[mode]))
        listener.listen(1)
        listener.settimeout(10)

        def server():
            conn, _ = listener.accept()
            with conn:
                peer(conn, True)

        with ThreadPoolExecutor(max_workers=1) as pool:
            done = pool.submit(server)
            with socket.create_connection(("127.0.0.1", PORTS[mode]), timeout=10) as conn:
                peer(conn, False)
            done.result()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--keylog", required=True, help="fresh normal/outer TLS NSS keylog")
    parser.add_argument("--inner-keylog", required=True, help="fresh HTTPS CONNECT inner TLS NSS keylog")
    parser.add_argument("--mode", choices=["all", *PORTS], default="all")
    args = parser.parse_args()
    for path in (args.keylog, args.inner_keylog):
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    for mode in (PORTS if args.mode == "all" else [args.mode]):
        for accepted in (False, True):
            run_exchange(args, mode, accepted)
        request, response = http_messages(mode)
        print(json.dumps(dict(mode=mode, port=PORTS[mode], connections=2,
                              request_sha256=hashlib.sha256(request).hexdigest(),
                              response_sha256=hashlib.sha256(response).hexdigest())), flush=True)


if __name__ == "__main__":
    main()
