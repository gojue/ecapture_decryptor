#!/usr/bin/env python3
"""Independent MQTT 3.1.1 and Redis RESP2/RESP3 TLS wire peers.

Run after starting a loopback capture on TCP ports 44440 and 44441.
Arguments: certificate, private key, fresh NSS keylog path, optional mqtt|redis.
Only Python's standard library is required. Each peer checks every wire byte;
no SDK parser code is imported and no synthetic capture packets are written.
"""
import os
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def mqtt_packet(first, body=b""):
    length = len(body)
    encoded = bytearray([first])
    while True:
        digit = length % 128
        length //= 128
        encoded.append(digit | (128 if length else 0))
        if not length:
            break
    return bytes(encoded) + body


def mqtt_field(data):
    return struct.pack("!H", len(data)) + data


def mqtt_steps():
    connect = mqtt_packet(0x10, b"\x00\x04MQTT\x04\x02\x00\x1e" + mqtt_field(b"fixture"))
    subscribe = mqtt_packet(0x82, b"\x00\x01" + mqtt_field(b"fixture/+") + b"\x02")
    qos0 = mqtt_packet(0x30, mqtt_field(b"fixture/client") + bytes(range(256)) * 2)
    qos1_body = mqtt_field(b"fixture/client") + b"\x00\x02qos1"
    qos2 = mqtt_packet(0x34, mqtt_field(b"fixture/client") + b"\x00\x03qos2")
    push = mqtt_packet(0x32, mqtt_field(b"fixture/server") + b"\x00\x07push")
    return [
        ("C", connect),
        ("S", b"\x20\x02\x00\x00"),
        ("C", subscribe),
        ("S", b"\x90\x03\x00\x01\x02"),
        ("C", qos0 + mqtt_packet(0x32, qos1_body)),  # Two coalesced publications.
        ("S", b"\x40\x02\x00\x02"),
        ("C", mqtt_packet(0x3a, qos1_body)),  # DUP is a second observed packet.
        ("S", b"\x40\x02\x00\x02"),
        ("C", qos2),
        ("S", b"\x50\x02\x00\x03"),
        ("C", b"\x62\x02\x00\x03"),
        ("S", b"\x70\x02\x00\x03" + push),
        ("C", b"\x40\x02\x00\x07\xc0\x00"),
        ("S", b"\xd0\x00"),
        ("C", mqtt_packet(0xa2, b"\x00\x04" + mqtt_field(b"fixture/+"))),
        ("S", b"\xb0\x02\x00\x04"),
        ("C", b"\xe0\x00"),
    ]


def resp(value):
    if isinstance(value, int):
        return b":" + str(value).encode() + b"\r\n"
    if isinstance(value, list):
        return b"*" + str(len(value)).encode() + b"\r\n" + b"".join(map(resp, value))
    if isinstance(value, str):
        value = value.encode()
    return b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"


def resp_push(values):
    return b">" + resp(values)[1:]


REDIS_VALUE = b"\x00fixture\r\n\xff"


def redis2_steps():
    return [
        ("C", resp(["SET", "key", REDIS_VALUE]) + resp(["GET", "key"])),
        ("S", b"+OK\r\n" + resp(REDIS_VALUE)),
        ("C", resp(["SUBSCRIBE", "alpha", "beta"])),
        ("S", resp(["subscribe", "alpha", 1]) + resp(["subscribe", "beta", 2])),
        ("S", resp(["message", "alpha", b"server-push"])),
        ("C", resp(["PING"])),
        ("S", resp(["pong", b""])),
        ("C", resp(["UNSUBSCRIBE"])),
        ("S", resp(["unsubscribe", "alpha", 1]) + resp(["unsubscribe", "beta", 0])),
        ("C", resp(["GET", "key"])),
        ("S", resp(REDIS_VALUE)),
    ]


def redis3_steps():
    return [
        ("C", resp(["HELLO", "3"])),
        ("S", b"%2\r\n" + resp("server") + resp("redis") + resp("proto") + resp(3)),
        ("C", resp(["GET", "key"])),
        ("S", b"|1\r\n+ttl\r\n:10\r\n" + resp_push(["invalidate", ["key"]]) + resp(REDIS_VALUE)),
        ("C", resp(["SUBSCRIBE", "alpha"])),
        ("S", resp_push(["subscribe", "alpha", 1]) + resp_push(["message", "alpha", b"server-push"])),
        ("C", resp(["UNSUBSCRIBE", "alpha"])),
        ("S", resp_push(["unsubscribe", "alpha", 0])),
        ("C", resp(["GET", "key"])),
        ("S", resp(REDIS_VALUE)),
    ]


def read_exact(conn, expected):
    data = bytearray()
    while len(data) < len(expected):
        fragment = conn.recv(len(expected) - len(data))
        assert fragment, "peer closed before completing its message"
        data.extend(fragment)
    assert bytes(data) == expected, "peer wire bytes differ"


def write_fragments(conn, data):
    # Separate TLS writes split fixed headers, length fields, and bodies.
    for part in (data[:1], data[1:3], data[3:]):
        if part:
            conn.sendall(part)
            time.sleep(.002)


def tls_exchange(cert, key, keylog, port, steps, alpn=None):
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE  # Ephemeral loopback certificate only.
    client_ctx.keylog_filename = keylog
    if alpn:
        server_ctx.set_alpn_protocols([alpn])
        client_ctx.set_alpn_protocols([alpn])
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(10)

        def server():
            conn, _ = listener.accept()
            with server_ctx.wrap_socket(conn, server_side=True) as conn:
                conn.settimeout(10)
                for direction, wire in steps:
                    if direction == "S":
                        write_fragments(conn, wire)
                    else:
                        read_exact(conn, wire)
                conn.unwrap().close()

        with ThreadPoolExecutor(max_workers=1) as pool:
            done = pool.submit(server)
            with client_ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname="localhost") as conn:
                for direction, wire in steps:
                    if direction == "C":
                        write_fragments(conn, wire)
                    else:
                        read_exact(conn, wire)
                conn.unwrap().close()
            done.result()
    print(f"TLS port {port}: {len(steps)} exchanges verified byte-for-byte", flush=True)


if __name__ == "__main__":
    if len(sys.argv) not in (4, 5):
        raise SystemExit("usage: d08_tcp.py cert key fresh-keylog [mqtt|redis]")
    cert, key, keylog = sys.argv[1:4]
    mode = sys.argv[4] if len(sys.argv) == 5 else "all"
    if mode not in ("all", "mqtt", "redis"):
        raise SystemExit("mode must be mqtt or redis")
    os.close(os.open(keylog, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    if mode in ("all", "mqtt"):
        tls_exchange(cert, key, keylog, 44440, mqtt_steps(), "mqtt")
        print("MQTT 3.1.1: 20 packets, QoS 0/1/2, DUP, subscribe, server push, ping, unsubscribe, disconnect", flush=True)
    if mode in ("all", "redis"):
        tls_exchange(cert, key, keylog, 44441, redis2_steps())
        tls_exchange(cert, key, keylog, 44441, redis3_steps())
        print("Redis: RESP2 15 values, RESP3 13 values, binary pipeline, pubsub, attribute and push", flush=True)
