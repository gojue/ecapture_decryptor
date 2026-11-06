#!/usr/bin/env python3
"""Independent DNS peers over DoT, DoH/1/2/3 and DoQ.

Start a loopback capture first. This program only creates real TLS/QUIC traffic,
never pcap files. Requires dnspython, hyper-h2 and aioquic 1.3.0 in a fixture venv.
Usage: dns_capture.py --cert CERT --key KEY --keylog FRESH_PATH [--mode all]
"""
# Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
# See LICENSE for the applicable license.

import argparse
import asyncio
import base64
import ssl
import struct
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import dns.flags
import dns.message
import dns.rrset
from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.events import DataReceived as H3Data, HeadersReceived as H3Headers
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived
from aioquic.tls import CipherSuite
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded

from aioquic_capture import StaticH3


def query(name, message_id=0):
    result = dns.message.make_query(name, "A", use_edns=False)
    result.id = message_id
    return result.to_wire()


def answer(wire):
    request = dns.message.from_wire(wire)
    assert not request.flags & dns.flags.QR
    assert len(request.question) == 1
    response = dns.message.make_response(request)
    response.flags |= dns.flags.RA
    response.answer.append(dns.rrset.from_text(request.question[0].name, 60, "IN", "A", "192.0.2.1"))
    return response.to_wire()


def verify(request, response):
    parsed_query = dns.message.from_wire(request)
    parsed_response = dns.message.from_wire(response)
    assert parsed_query.is_response(parsed_response)
    assert response == answer(request)
    assert parsed_response.answer[0][0].address == "192.0.2.1"


def envelope(wire):
    return struct.pack("!H", len(wire)) + wire


def doh_query(headers, body):
    method = headers[":method"]
    if method == "GET":
        encoded = parse_qs(urlsplit(headers[":path"]).query)["dns"]
        assert len(encoded) == 1 and not body
        return base64.urlsafe_b64decode(encoded[0] + "=" * (-len(encoded[0]) % 4))
    assert method == "POST"
    assert headers["content-type"] == "application/dns-message"
    return bytes(body)


def doh_headers(mode, method):
    wire = query(f"{mode}-{method.lower()}.example.")
    path = "/dns-query"
    if method == "GET":
        path += "?dns=" + base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
    headers = [(":method", method), (":scheme", "https"), (":authority", "localhost"),
               (":path", path), ("accept", "application/dns-message")]
    if method == "POST":
        headers += [("content-type", "application/dns-message"), ("content-length", str(len(wire)))]
    return headers, wire


def tls_contexts(args, alpn):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(args.cert, args.key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE  # Isolated ephemeral loopback fixture.
    client.keylog_filename = args.keylog
    for ctx in (client, server):
        ctx.set_alpn_protocols([alpn])
    return client, server


async def tls_peers(args, port, alpn, server_peer, client_peer, count=1):
    client_ctx, server_ctx = tls_contexts(args, alpn)
    finished = asyncio.Queue()

    async def handler(reader, writer):
        error = None
        try:
            assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == alpn
            await server_peer(reader, writer)
        except Exception as exc:
            error = exc
        finally:
            writer.close()
            await writer.wait_closed()
            finished.put_nowait(error)

    async with await asyncio.start_server(handler, "127.0.0.1", port, ssl=server_ctx):
        for index in range(count):
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx, server_hostname="localhost")
            try:
                assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == alpn
                await asyncio.wait_for(client_peer(reader, writer, index), 10)
            finally:
                writer.close()
                await writer.wait_closed()
            error = await asyncio.wait_for(finished.get(), 10)
            if error:
                raise error


async def run_dot(args):
    async def server(reader, writer):
        requests = []
        for _ in range(2):
            length = struct.unpack("!H", await reader.readexactly(2))[0]
            wire = await reader.readexactly(length)
            assert dns.message.from_wire(wire).id in (7, 8)
            requests.append(wire)
        output = b"".join(envelope(answer(wire)) for wire in reversed(requests))
        writer.write(output[:1])
        await writer.drain()
        await asyncio.sleep(.01)
        writer.write(output[1:])
        await writer.drain()
        assert not await reader.read()

    async def client(reader, writer, index):
        requests = [query(f"dot-c{index}-{suffix}.example.", message_id) for suffix, message_id in (("one", 7), ("two", 8))]
        data = b"".join(envelope(wire) for wire in requests)
        for part in (data[:1], data[1:9], data[9:]):
            writer.write(part)
            await writer.drain()
            await asyncio.sleep(.01)
        for request in reversed(requests):
            length = struct.unpack("!H", await reader.readexactly(2))[0]
            verify(request, await reader.readexactly(length))

    await tls_peers(args, 44439, "dot", server, client, count=2)
    print("DoT: two connections, reused IDs 7/8, four queries, reversed responses verified", flush=True)


async def read_http1(reader):
    block = await reader.readuntil(b"\r\n\r\n")
    lines = block.decode("ascii").split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:] if line)
    headers = {k.lower(): v for k, v in headers.items()}
    body = bytearray()
    if headers.get("transfer-encoding") == "chunked":
        while True:
            size = int((await reader.readline()).strip(), 16)
            if size == 0:
                assert await reader.readline() == b"\r\n"
                break
            body.extend(await reader.readexactly(size))
            assert await reader.readexactly(2) == b"\r\n"
    elif "content-length" in headers:
        body.extend(await reader.readexactly(int(headers["content-length"])))
    return lines[0], headers, bytes(body)


async def run_doh1(args):
    async def server(reader, writer):
        for _ in range(2):
            line, headers, body = await read_http1(reader)
            method, path, version = line.split(" ")
            assert version == "HTTP/1.1"
            headers.update({":method": method, ":path": path})
            wire = doh_query(headers, body)
            response = answer(wire)
            if method == "GET":
                output = f"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {len(response)}\r\n\r\n".encode() + response
            else:
                output = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n"
                for part in (response[:7], response[7:]):
                    output += f"{len(part):x}\r\n".encode() + part + b"\r\n"
                output += b"0\r\n\r\n"
            writer.write(output)
            await writer.drain()
        assert not await reader.read()

    async def client(reader, writer, _index):
        for method in ("GET", "POST"):
            fields, wire = doh_headers("doh1", method)
            h = dict(fields)
            block = f"{method} {h[':path']} HTTP/1.1\r\nHost: localhost\r\n".encode()
            block += b"".join(f"{k}: {v}\r\n".encode() for k, v in fields if not k.startswith(":")) + b"\r\n"
            body = wire if method == "POST" else b""
            for part in (block[:4], block[4:] + body[:3], body[3:]):
                if part:
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(.01)
            line, headers, response = await read_http1(reader)
            assert line == "HTTP/1.1 200 OK" and headers["content-type"] == "application/dns-message"
            verify(wire, response)

    await tls_peers(args, 44442, "http/1.1", server, client)
    print("DoH/1: GET base64url + POST, fragmented TLS, length/chunked responses verified", flush=True)


async def run_doh2(args):
    async def server(reader, writer):
        h = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
        h.initiate_connection()
        writer.write(h.data_to_send())
        await writer.drain()
        requests, ended = {}, set()
        while len(ended) < 2:
            data = await reader.read(65536)
            assert data
            for event in h.receive_data(data):
                if isinstance(event, RequestReceived):
                    requests[event.stream_id] = [dict(event.headers), bytearray()]
                elif isinstance(event, DataReceived):
                    requests[event.stream_id][1].extend(event.data)
                    h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    ended.add(event.stream_id)
        for stream in (3, 1):
            response = answer(doh_query(*requests[stream]))
            h.send_headers(stream, [(":status", "200"), ("content-type", "application/dns-message"), ("content-length", str(len(response)))])
            h.send_data(stream, response[:7])
            h.send_data(stream, response[7:], end_stream=True)
        writer.write(h.data_to_send())
        await writer.drain()
        assert not await reader.read()

    async def client(reader, writer, _index):
        h = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
        h.initiate_connection()
        wanted, received = {}, {1: bytearray(), 3: bytearray()}
        for stream, method in ((1, "GET"), (3, "POST")):
            headers, wire = doh_headers("doh2", method)
            wanted[stream] = wire
            h.send_headers(stream, headers, end_stream=method == "GET")
            if method == "POST":
                h.send_data(stream, wire[:3])
                h.send_data(stream, wire[3:], end_stream=True)
        writer.write(h.data_to_send())
        await writer.drain()
        ended = set()
        while len(ended) < 2:
            data = await reader.read(65536)
            assert data
            for event in h.receive_data(data):
                if isinstance(event, ResponseReceived):
                    headers = dict(event.headers)
                    assert headers[":status"] == "200" and headers["content-type"] == "application/dns-message"
                elif isinstance(event, DataReceived):
                    received[event.stream_id].extend(event.data)
                elif isinstance(event, StreamEnded):
                    ended.add(event.stream_id)
        for stream in wanted:
            verify(wanted[stream], bytes(received[stream]))

    await tls_peers(args, 44443, "h2", server, client)
    print("DoH/2: GET/POST multiplexed streams 1/3, reversed responses verified", flush=True)


class DoQ(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buffers, self.futures, self.queries = {}, {}, {}

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            assert event.alpn_protocol == "doq"
        if not isinstance(event, StreamDataReceived):
            return
        buf = self.buffers.setdefault(event.stream_id, bytearray())
        buf.extend(event.data)
        if not event.end_stream:
            return
        assert len(buf) == 2 + struct.unpack("!H", buf[:2])[0]
        wire = bytes(buf[2:])
        assert dns.message.from_wire(wire).id == 0
        if self._quic.configuration.is_client:
            verify(self.queries[event.stream_id], wire)
            self.futures[event.stream_id].set_result(True)
        else:
            self._quic.send_stream_data(event.stream_id, envelope(answer(wire)), end_stream=True)
            self.transmit()
        del self.buffers[event.stream_id]

    async def request(self, name):
        stream = self._quic.get_next_available_stream_id()
        wire = query(name)
        self.queries[stream] = wire
        self.futures[stream] = asyncio.get_running_loop().create_future()
        data = envelope(wire)
        self._quic.send_stream_data(stream, data[:1])
        self.transmit()
        await asyncio.sleep(.01)
        self._quic.send_stream_data(stream, data[1:], end_stream=True)
        self.transmit()
        await asyncio.wait_for(self.futures[stream], 10)


class DoH3(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = StaticH3(self._quic)
        self.headers, self.bodies, self.futures, self.queries = {}, {}, {}, {}

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            assert event.alpn_protocol == "h3"
        for ev in self.http.handle_event(event):
            if isinstance(ev, H3Headers):
                self.headers[ev.stream_id] = {k.decode(): v.decode() for k, v in ev.headers}
                self.bodies.setdefault(ev.stream_id, bytearray())
            elif isinstance(ev, H3Data):
                self.bodies[ev.stream_id].extend(ev.data)
            if isinstance(ev, (H3Headers, H3Data)) and ev.stream_ended:
                headers, body = self.headers[ev.stream_id], bytes(self.bodies[ev.stream_id])
                if self._quic.configuration.is_client:
                    assert headers[":status"] == "200" and headers["content-type"] == "application/dns-message"
                    verify(self.queries[ev.stream_id], body)
                    self.futures[ev.stream_id].set_result(True)
                else:
                    response = answer(doh_query(headers, body))
                    self.http.send_headers(ev.stream_id, [(b":status", b"200"), (b"content-type", b"application/dns-message"), (b"content-length", str(len(response)).encode())])
                    self.http.send_data(ev.stream_id, response[:7], end_stream=False)
                    self.http.send_data(ev.stream_id, response[7:], end_stream=True)
                    self.transmit()

    async def request(self, method):
        stream = self._quic.get_next_available_stream_id()
        headers, wire = doh_headers("doh3", method)
        self.queries[stream] = wire
        self.futures[stream] = asyncio.get_running_loop().create_future()
        self.http.send_headers(stream, [(k.encode(), v.encode()) for k, v in headers], end_stream=method == "GET")
        if method == "POST":
            self.http.send_data(stream, wire[:3], end_stream=False)
            self.http.send_data(stream, wire[3:], end_stream=True)
        self.transmit()
        await asyncio.wait_for(self.futures[stream], 10)


async def run_quic(args, mode):
    alpn, port, protocol = ("doq", 44444, DoQ) if mode == "doq" else ("h3", 44445, DoH3)
    with Path(args.keylog).open("a") as keys:
        common = dict(alpn_protocols=[alpn], supported_versions=[1], cipher_suites=[CipherSuite.AES_128_GCM_SHA256], secrets_log_file=keys)
        server_config = QuicConfiguration(is_client=False, **common)
        server_config.load_cert_chain(args.cert, args.key)
        server = await serve("127.0.0.1", port, configuration=server_config, create_protocol=protocol)
        try:
            for index in range(2 if mode == "doq" else 1):
                config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE, **common)
                async with connect("127.0.0.1", port, configuration=config, create_protocol=protocol) as client:
                    names = [f"doq-c{index}-one.example.", f"doq-c{index}-two.example."] if mode == "doq" else ["GET", "POST"]
                    await asyncio.gather(*(client.request(name) for name in names))
                    await asyncio.sleep(.05)
        finally:
            server.close()
            await asyncio.sleep(.05)
    print(f"{mode}: QUIC v1 AES128, parallel streams, DNS bytes and ALPN verified", flush=True)


async def run(args):
    with Path(args.keylog).open("x"):
        pass
    for mode in (["dot", "doh1", "doh2", "doq", "doh3"] if args.mode == "all" else [args.mode]):
        if mode in ("doq", "doh3"):
            await run_quic(args, mode)
        else:
            await {"dot": run_dot, "doh1": run_doh1, "doh2": run_doh2}[mode](args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--keylog", required=True)
    parser.add_argument("--mode", choices=["all", "dot", "doh1", "doh2", "doq", "doh3"], default="all")
    asyncio.run(run(parser.parse_args()))
