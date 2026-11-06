#!/usr/bin/env python3
"""Independent TLS peers. Requires websockets 15.0.1 and h2 4.3.0.

Run after starting dumpcap on loopback TCP ports 44437 and 44438.
Arguments: ephemeral certificate, private key, fresh NSS keylog path.
No SDK code is imported. Every peer checks received message bytes.
"""
import gzip
import ssl
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from socket import create_connection, socket

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded, TrailersReceived, ResponseReceived
from websockets.exceptions import ConnectionClosedOK
from websockets.sync.client import connect
from websockets.sync.server import serve
from websockets.extensions.permessage_deflate import ClientPerMessageDeflateFactory, ServerPerMessageDeflateFactory


def contexts(cert, key, keylog, alpn):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE  # Ephemeral loopback certificate only.
    client.keylog_filename = keylog
    for ctx in (client, server):
        ctx.set_alpn_protocols([alpn])
    return client, server


def websocket_fixture(cert, key, keylog):
    client_ctx, server_ctx = contexts(cert, key, keylog, "http/1.1")
    for no_context in (False, True):
        errors = []
        def handler(ws):
            try:
                for i in range(3):
                    text = ("websocket-request-%d-" % i) * 100
                    assert ws.recv() == text
                    # Binary response fragmented by the independent implementation.
                    reply = (("websocket-response-%d-" % i) * 100).encode()
                    ws.send([reply[:100], reply[100:]])
                    assert ws.ping(b"server-ping").wait(3)
                try:
                    ws.recv()  # Let the client finish its final ping and close.
                    raise AssertionError("unexpected extra message")
                except ConnectionClosedOK:
                    pass
            except Exception as exc:
                errors.append(exc)
                raise
        kwargs = dict(server_no_context_takeover=no_context, client_no_context_takeover=no_context,
                      server_max_window_bits=12, client_max_window_bits=12)
        with serve(handler, "127.0.0.1", 44437, ssl=server_ctx, compression=None,
                   extensions=[ServerPerMessageDeflateFactory(**kwargs)]) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with connect("wss://127.0.0.1:44437/chat", ssl=client_ctx, compression=None,
                             extensions=[ClientPerMessageDeflateFactory(**kwargs)]) as ws:
                    for i in range(3):
                        text = ("websocket-request-%d-" % i) * 100
                        ws.send([text[:50], text[50:]])
                        assert ws.recv() == (("websocket-response-%d-" % i) * 100).encode()
                        assert ws.ping(b"client-ping").wait(3)
                        time.sleep(.02)
            finally:
                server.shutdown()
                thread.join()
        assert not errors, errors
    print("WebSocket: both directions, fragmentation, controls, takeover on/off verified", flush=True)


COUNTS = {1: (1, 1), 3: (3, 1), 5: (1, 3), 7: (3, 3), 9: (0, 0)}


def message(direction, stream, index):
    text = f"{direction}-{stream}-{index}".encode()
    return b"\x0a" + bytes([len(text)]) + text  # Opaque protobuf bytes, no descriptor.


def envelope(payload, compressed):
    data = gzip.compress(payload, mtime=0) if compressed else payload
    return struct.pack("!BI", int(compressed), len(data)) + data


def send_message(h2, stream, payload, index):
    data = envelope(payload, index % 2 == 0)
    # Prefix split across DATA frames; the rest contains gzip header/body/footer.
    for part in (data[:2], data[2:4], data[4:8], data[8:]):
        if part:
            h2.send_data(stream, part)


def unpack(buf):
    result = []
    while len(buf) >= 5:
        compressed, size = struct.unpack("!BI", buf[:5])
        if len(buf) < size + 5:
            break
        data = bytes(buf[5:size + 5])
        del buf[:size + 5]
        result.append(gzip.decompress(data) if compressed else data)
    return result


def grpc_fixture(cert, key, keylog):
    client_ctx, server_ctx = contexts(cert, key, keylog, "h2")
    listener = socket()
    listener.bind(("127.0.0.1", 44438))
    listener.listen(1)

    def server():
        conn, _ = listener.accept()
        with server_ctx.wrap_socket(conn, server_side=True) as conn:
            conn.settimeout(10)
            h = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
            h.initiate_connection()
            conn.sendall(h.data_to_send())
            buffers = {s: bytearray() for s in COUNTS}
            received = {s: [] for s in COUNTS}
            ended = set()
            while len(ended) < len(COUNTS):
                wire = conn.recv(65536)
                assert wire
                for event in h.receive_data(wire):
                    if isinstance(event, RequestReceived):
                        assert dict(event.headers)["content-type"] == "application/grpc+proto"
                        headers = [(":status", "200"), ("content-type", "application/grpc+proto"), ("grpc-encoding", "gzip")]
                        if event.stream_id == 9:
                            headers += [("grpc-status", "13"), ("grpc-message", "trailers%20only")]
                        h.send_headers(event.stream_id, headers, end_stream=event.stream_id == 9)
                    elif isinstance(event, DataReceived):
                        s = event.stream_id
                        buffers[s].extend(event.data)
                        for value in unpack(buffers[s]):
                            i = len(received[s])
                            assert value == message("request", s, i)
                            received[s].append(value)
                            if s == 7:  # Deliver bidi replies before client END_STREAM.
                                send_message(h, s, message("response", s, i), i)
                        h.acknowledge_received_data(event.flow_controlled_length, s)
                    elif isinstance(event, StreamEnded):
                        s = event.stream_id
                        assert not buffers[s]
                        assert len(received[s]) == COUNTS[s][0]
                        if s not in (7, 9):
                            for i in range(COUNTS[s][1]):
                                send_message(h, s, message("response", s, i), i)
                        if s != 9:
                            h.send_headers(s, [("grpc-status", "5" if s == 3 else "0"),
                                               ("grpc-message", "fixture%20done")], end_stream=True)
                        ended.add(s)
                conn.sendall(h.data_to_send())
            time.sleep(.05)

    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(server)
        with client_ctx.wrap_socket(create_connection(("127.0.0.1", 44438)), server_hostname="localhost") as conn:
            conn.settimeout(10)
            h = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
            h.initiate_connection()
            for s in COUNTS:
                h.send_headers(s, [(":method", "POST"), (":scheme", "https"), (":authority", "localhost"),
                                   (":path", f"/fixture.Service/Call{s}"), ("te", "trailers"),
                                   ("content-type", "application/grpc+proto"), ("grpc-encoding", "gzip")], end_stream=s == 9)
            conn.sendall(h.data_to_send())
            for i in range(3):
                for s, (n, _) in COUNTS.items():
                    if i < n:
                        send_message(h, s, message("request", s, i), i)
                        if i == n - 1:
                            h.end_stream(s)
                conn.sendall(h.data_to_send())
                time.sleep(.02)
            buffers = {s: bytearray() for s in COUNTS}
            received = {s: [] for s in COUNTS}
            status, ended = {}, set()
            while len(ended) < len(COUNTS):
                wire = conn.recv(65536)
                assert wire
                for event in h.receive_data(wire):
                    if isinstance(event, DataReceived):
                        s = event.stream_id
                        buffers[s].extend(event.data)
                        received[s].extend(unpack(buffers[s]))
                        h.acknowledge_received_data(event.flow_controlled_length, s)
                    elif isinstance(event, (ResponseReceived, TrailersReceived)):
                        headers = dict(event.headers)
                        if "grpc-status" in headers:
                            status[event.stream_id] = headers["grpc-status"]
                    elif isinstance(event, StreamEnded):
                        ended.add(event.stream_id)
                conn.sendall(h.data_to_send())
            for s, (_, count) in COUNTS.items():
                assert not buffers[s]
                assert received[s] == [message("response", s, i) for i in range(count)]
                assert status[s] == ("13" if s == 9 else "5" if s == 3 else "0")
        result.result()
    listener.close()
    print("gRPC/H2: unary, client/server/bidi streaming, gzip, errors, trailers-only verified", flush=True)


if __name__ == "__main__":
    cert, key, keylog = sys.argv[1:]
    with open(keylog, "x"):
        pass
    websocket_fixture(cert, key, keylog)
    grpc_fixture(cert, key, keylog)
