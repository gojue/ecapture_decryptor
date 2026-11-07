#!/usr/bin/env python3
"""Generate independent QUIC lifecycle traffic (aioquic 1.3.0).

Capture real loopback UDP separately (ports depend on mode); this program never writes pcap.
Usage: python aioquic_capture.py --cert cert.pem --key key.pem --output DIR
"""
# Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
# See LICENSE for the applicable license.
import argparse
import asyncio
import hashlib
import hmac
import json
import ssl
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3Connection, Setting, FrameType, HeadersState, encode_frame
from aioquic.h3.events import DataReceived, HeadersReceived, PushPromiseReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived, HandshakeCompleted, StreamReset
from aioquic.quic.logger import QuicLogger
from aioquic.tls import CipherSuite, Epoch


class StaticH3(H3Connection):
    def _get_local_settings(self):
        settings = super()._get_local_settings()
        settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0
        settings[Setting.QPACK_BLOCKED_STREAMS] = 0
        return settings


class HTTP(QuicConnectionProtocol):
    evidence = []
    h3_class = StaticH3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = self.h3_class(self._quic)
        self.paths = {}
        self.responses = {}
        self.handshake = None

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = event
            # Pinned-generator introspection verifies actual negotiated values.
            if self._quic.configuration.is_client:
                self.evidence.append(dict(
                    version=hex(self._quic._version),
                    suite=self._quic.tls.key_schedule.cipher_suite.name,
                    resumed=event.session_resumed,
                    early_accepted=event.early_data_accepted,
                ))
        for h3 in self.http.handle_event(event):
            if isinstance(h3, HeadersReceived):
                self.paths[h3.stream_id] = dict(h3.headers).get(b":path", b"")
            if isinstance(h3, (HeadersReceived, DataReceived)) and h3.stream_ended:
                if self._quic.configuration.is_client:
                    self.responses[h3.stream_id].set_result(True)
                else:
                    body = b"reply " + self.paths[h3.stream_id]
                    self.http.send_headers(h3.stream_id, [(b":status", b"200"), (b"content-length", str(len(body)).encode())])
                    self.http.send_data(h3.stream_id, body, end_stream=True)
                    self.transmit()

    async def request(self, path):
        stream = self._quic.get_next_available_stream_id()
        self.responses[stream] = asyncio.get_running_loop().create_future()
        self.http.send_headers(stream, [(b":method", b"GET"), (b":scheme", b"https"),
                                      (b":authority", b"localhost"), (b":path", path.encode())], end_stream=True)
        self.transmit()
        await asyncio.wait_for(self.responses[stream], 10)


class DynamicH3(H3Connection):
    """Pinned aioquic 1.3.0 adapter: retain INITIAL after a 1xx section.

    QPACK encoding/decoding stays in independent pylsqpack. Delays below affect
    actual encoder-stream writes, so dumpcap records real blocked network traffic.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hold_encoder = False
        self.pending_encoder = bytearray()
        self.sections = []
        self.flush_task = None
        self.transmit = None
        self.fragmented = 0

    def _handle_request_or_push_frame(self, frame_type, frame_data, stream, stream_ended):
        events = super()._handle_request_or_push_frame(frame_type, frame_data, stream, stream_ended)
        for event in events:
            if isinstance(event, HeadersReceived) and dict(event.headers).get(b":status", b"").startswith(b"1"):
                stream.headers_recv_state = HeadersState.INITIAL
        return events

    def _encode_headers(self, stream_id, headers):
        encoder, block = self._encoder.encode(stream_id, headers)
        self._encoder_bytes_sent += len(encoder)
        self.sections.append(dict(stream=stream_id, block=block.hex(), encoder=encoder.hex()))
        if self.hold_encoder and encoder:
            self.pending_encoder.extend(encoder)
            if self.flush_task is None or self.flush_task.done():
                self.flush_task = asyncio.create_task(self.flush_encoder())
        else:
            self._quic.send_stream_data(self._local_encoder_stream_id, encoder)
        return block

    async def flush_encoder(self):
        await asyncio.sleep(0.08)
        while self.pending_encoder:
            data = bytes(self.pending_encoder)
            self.pending_encoder.clear()
            self._quic.send_stream_data(self._local_encoder_stream_id, data[:1])
            self.transmit()
            await asyncio.sleep(0.02)
            self._quic.send_stream_data(self._local_encoder_stream_id, data[1:])
            self.transmit()
            self.fragmented += 1

    def send_informational(self, stream):
        block = self._encode_headers(stream, [(b":status", b"103"), (b"link", b"</asset>; rel=preload")])
        self._quic.send_stream_data(stream, encode_frame(FrameType.HEADERS, block))


class DynamicHTTP(HTTP):
    h3_class = DynamicH3
    instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http.transmit = self.transmit
        self.events = []
        self.instances.append(self)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = event
        if isinstance(event, StreamReset):
            self.events.append(dict(kind="reset", stream=event.stream_id, code=event.error_code))
            future = self.responses.get(event.stream_id)
            if future is not None and not future.done():
                future.set_result(True)
        for h3 in self.http.handle_event(event):
            if self._quic.configuration.is_client:
                record = dict(kind=type(h3).__name__, stream=h3.stream_id, push=getattr(h3, "push_id", None))
                if isinstance(h3, (HeadersReceived, PushPromiseReceived)):
                    record["headers"] = [(k.decode(), v.decode()) for k, v in h3.headers]
                if isinstance(h3, DataReceived):
                    record["body"] = h3.data.decode()
                self.events.append(record)
                if isinstance(h3, (HeadersReceived, DataReceived)) and h3.stream_ended and h3.push_id is None:
                    self.responses[h3.stream_id].set_result(True)
            else:
                if isinstance(h3, HeadersReceived):
                    self.paths[h3.stream_id] = dict(h3.headers)[b":path"]
                if isinstance(h3, (HeadersReceived, DataReceived)) and h3.stream_ended:
                    self.reply(h3.stream_id)

    def reply(self, stream):
        path = self.paths[stream]
        label = path.split(b"/")[1]
        self.http.hold_encoder = not path.endswith(b"warmup")
        if path.endswith(b"reset"):
            self.http.send_headers(stream, [(b":status", b"200")])
            self.http.send_data(stream, b"discarded partial response", end_stream=False)
            self.transmit()
            def reset():
                self._quic.reset_stream(stream, 0x10c)
                self.transmit()
            asyncio.get_running_loop().call_later(0.02, reset)
            return
        if not path.endswith(b"warmup"):
            self.http.send_informational(stream)
        if path.endswith(b"one"):
            pushed = self.http.send_push_promise(stream, [(b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", b"localhost"), (b":path", b"/" + label + b"/asset")])
            body = b"asset " + label
            self.http.send_headers(pushed, [(b":status", b"200"), (b"content-length", str(len(body)).encode())])
            self.http.send_data(pushed, body, end_stream=True)
        body = b"reply " + path
        self.http.send_headers(stream, [(b":status", b"200"), (b"x-fixture-token", label * 16),
            (b"content-length", str(len(body)).encode())])
        self.http.send_data(stream, body, end_stream=False)
        self.http.send_headers(stream, [(b"x-finished", label)], end_stream=True)
        self.transmit()

    async def request(self, path):
        stream = self._quic.get_next_available_stream_id()
        self.responses[stream] = asyncio.get_running_loop().create_future()
        label = path.split("/")[1].encode()
        self.http.hold_encoder = not path.endswith("warmup")
        self.http.send_headers(stream, [(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", path.encode()), (b"x-fixture-token", label * 16)], end_stream=True)
        self.transmit()
        await asyncio.wait_for(self.responses[stream], 10)


def validate_dynamic(events, label):
    for stream, suffix in [(0, "warmup"), (4, "one"), (8, "two")]:
        headers = [dict(e["headers"]) for e in events if e["kind"] == "HeadersReceived" and e["stream"] == stream]
        statuses = [h[":status"] for h in headers if ":status" in h]
        assert statuses == (["200"] if stream == 0 else ["103", "200"])
        assert any(h.get("x-fixture-token") == label * 16 for h in headers)
        assert headers[-1] == {"x-finished": label}
        body = "".join(e["body"] for e in events if e["kind"] == "DataReceived" and e["stream"] == stream)
        assert body == f"reply /{label}/{suffix}"
    promises = [e for e in events if e["kind"] == "PushPromiseReceived"]
    assert len(promises) == 1 and promises[0]["stream"] == 4 and promises[0]["push"] == 0
    assert dict(promises[0]["headers"])[":path"] == f"/{label}/asset"
    pushed = "".join(e["body"] for e in events if e["kind"] == "DataReceived" and e["stream"] == 15)
    assert pushed == f"asset {label}"
    resets = [e for e in events if e["kind"] == "reset"]
    assert resets == [dict(kind="reset", stream=12, code=0x10c)]


async def run_dynamic(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    qlog = QuicLogger()
    version = 1 if args.version == 1 else 0x6B3343CF
    suite = CipherSuite.AES_256_GCM_SHA384 if args.version == 1 else CipherSuite.AES_128_GCM_SHA256
    with (output / "dynamic.keys").open("w") as secrets:
        config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], secrets_log_file=secrets, quic_logger=qlog,
            supported_versions=[version], cipher_suites=[suite])
        config.load_cert_chain(args.cert, args.key)
        server = await serve("127.0.0.1", 44433, configuration=config, create_protocol=DynamicHTTP)
        try:
            for label in ["alpha", "beta"]:
                client_config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE,
                    secrets_log_file=secrets, quic_logger=qlog, supported_versions=[version], cipher_suites=[suite])
                async with connect("127.0.0.1", 44433, configuration=client_config, create_protocol=DynamicHTTP) as client:
                    await client.request(f"/{label}/warmup")
                    await asyncio.gather(client.request(f"/{label}/one"), client.request(f"/{label}/two"))
                    await client.request(f"/{label}/reset")
                    await asyncio.sleep(0.2)
                    validate_dynamic(client.events, label)
                    assert client.handshake is not None
                    assert client._quic._version == version
                    assert client._quic.tls.key_schedule.cipher_suite == suite
        finally:
            server.close()
    evidence = [dict(client=p._quic.configuration.is_client, version=hex(p._quic._version),
        suite=p._quic.tls.key_schedule.cipher_suite.name, events=p.events,
        sections=p.http.sections, fragmented=p.http.fragmented) for p in DynamicHTTP.instances]
    assert len(evidence) == 4
    for item in evidence:
        assert item["fragmented"] > 0
        assert any(bytes.fromhex(s["block"])[0] != 0 for s in item["sections"])
        if item["client"]:
            assert sum(e["kind"] == "StreamReset" or e["kind"] == "reset" for e in item["events"]) == 1
            assert any(e["kind"] == "PushPromiseReceived" for e in item["events"])
    (output / "dynamic.qlog").write_text(json.dumps(qlog.to_dict()))
    (output / "dynamic-evidence.json").write_text(json.dumps(evidence, indent=2))
    print(f"D05 v{args.version}: two connections, dynamic QPACK in both directions, delayed/fragmented encoder, 103/final/trailers, push and reset")


class EarlyResetHTTP(HTTP):
    """Static QPACK isolates the early RESET state from dynamic-table testing."""
    instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = {}
        self.bodies = {}
        self.resets = []
        self.instances.append(self)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = event
        if isinstance(event, StreamReset):
            self.resets.append(dict(stream=event.stream_id, code=event.error_code))
        for h3 in self.http.handle_event(event):
            if isinstance(h3, HeadersReceived):
                self.headers[h3.stream_id] = dict(h3.headers)
                self.paths[h3.stream_id] = self.headers[h3.stream_id].get(b":path", b"")
            if isinstance(h3, DataReceived):
                self.bodies.setdefault(h3.stream_id, bytearray()).extend(h3.data)
            if isinstance(h3, (HeadersReceived, DataReceived)) and h3.stream_ended:
                if self._quic.configuration.is_client:
                    self.responses[h3.stream_id].set_result(True)
                else:
                    body = b"reply " + self.paths[h3.stream_id]
                    self.http.send_headers(h3.stream_id, [(b":status", b"200"), (b"content-length", str(len(body)).encode())])
                    self.http.send_data(h3.stream_id, body, end_stream=True)
                    self.transmit()

    async def request(self, path):
        stream = self._quic.get_next_available_stream_id()
        await super().request(path)
        assert self.headers[stream][b":status"] == b"200"
        assert self.bodies[stream] == b"reply " + path.encode()
        return stream

    def cancel_early_request(self):
        stream = self._quic.get_next_available_stream_id()
        assert stream == 0 and self.handshake is None
        self.http.send_headers(stream, [(b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", b"/early/reset"), (b"content-length", b"64")])
        self.http.send_data(stream, b"partial\x00\xff", end_stream=False)
        self.transmit()
        sender = self._quic._streams[stream].sender
        final_size = sender.highest_offset
        # No event-loop yield: the real prefix must leave before RESET, while
        # server handshake data cannot yet change the client's sending epoch.
        assert final_size > 0 and sender._buffer_start == 0
        prefix = bytes(sender._buffer[:final_size])
        self._quic.reset_stream(stream, 0x10c)
        self.transmit()
        return prefix, final_size


def reset_frames(peer, event_name):
    return [dict(packet_type=e["data"]["header"]["packet_type"], **frame)
        for e in peer._quic._quic_logger.to_dict()["events"]
        if e["name"] == event_name
        for frame in e["data"].get("frames", []) if frame["frame_type"] == "reset_stream"]


async def run_early_reset(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    qlog, evidence = QuicLogger(), []
    suite = CipherSuite.AES_128_GCM_SHA256
    with (output / "early-reset.keys").open("w") as secrets:
        for number, version, port in [(1, 1, 44467), (2, 0x6B3343CF, 44468)]:
            tickets, received = {}, []
            common = dict(alpn_protocols=["h3"], supported_versions=[version], cipher_suites=[suite],
                secrets_log_file=secrets, quic_logger=qlog)
            config = QuicConfiguration(is_client=False, **common)
            config.load_cert_chain(args.cert, args.key)
            for mode in ["seed", "accepted", "rejected"]:
                if mode == "rejected":
                    tickets.clear()
                start = len(EarlyResetHTTP.instances)
                server = await serve("127.0.0.1", port, configuration=config, create_protocol=EarlyResetHTTP,
                    session_ticket_fetcher=tickets.get,
                    session_ticket_handler=lambda ticket: tickets.__setitem__(ticket.ticket, ticket))
                try:
                    client_config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE,
                        session_ticket=received[-1] if mode != "seed" else None, **common)
                    async with connect("127.0.0.1", port, configuration=client_config, create_protocol=EarlyResetHTTP,
                            session_ticket_handler=received.append, wait_connected=(mode == "seed")) as client:
                        prefix, final_size = b"", 0
                        if mode != "seed":
                            prefix, final_size = client.cancel_early_request()
                            await client.wait_connected()
                        assert client.handshake.early_data_accepted == (mode == "accepted")
                        assert client._quic._version == version
                        assert client._quic.tls.key_schedule.cipher_suite == suite
                        path = f"/v{number}/{mode}/ok"
                        stream = await client.request(path)
                        assert stream == (0 if mode == "seed" else 4)
                        peers = [p for p in EarlyResetHTTP.instances[start:] if not p._quic.configuration.is_client]
                        assert len(peers) == 1
                        peer = peers[0]
                        if mode != "seed":
                            for _ in range(200):
                                if peer.resets:
                                    break
                                await asyncio.sleep(0.01)
                            assert peer.resets == [dict(stream=0, code=0x10c)]
                            if mode == "accepted":
                                assert peer.headers[0][b":path"] == b"/early/reset"
                                assert peer.headers[0][b"content-length"] == b"64"
                                assert peer.bodies[0] == b"partial\x00\xff"
                            else:
                                assert 0 not in peer.headers and 0 not in peer.bodies
                        await asyncio.sleep(0.05)
                        sent, seen = reset_frames(client, "transport:packet_sent"), reset_frames(peer, "transport:packet_received")
                        if mode != "seed":
                            reset = dict(error_code=0x10c, final_size=final_size, frame_type="reset_stream", stream_id=0)
                            levels = ["0RTT"] if mode == "accepted" else ["0RTT", "1RTT"]
                            assert sent == [dict(packet_type=level, **reset) for level in levels]
                            assert seen == [dict(packet_type=levels[-1], **reset)]
                            assert any(e["name"] == "transport:packet_sent" and
                                e["data"]["header"]["packet_type"] == "0RTT" and any(
                                    f["frame_type"] == "stream" and f["stream_id"] == 0 and
                                    f["offset"] == 0 and f["length"] == final_size and not f["fin"]
                                    for f in e["data"].get("frames", []))
                                for e in client._quic._quic_logger.to_dict()["events"])
                        evidence.append(dict(version=hex(version), mode=mode, path=path, normal_stream=stream,
                            suite=suite.name, early_accepted=client.handshake.early_data_accepted,
                            partial_prefix=prefix.hex(), final_size=final_size, sent_resets=sent, received_resets=seen,
                            received_partial=bytes(peer.bodies.get(0, b"")).hex() if mode != "seed" else ""))
                finally:
                    server.close()
                await asyncio.sleep(0.05)
    (output / "early-reset.qlog").write_text(json.dumps(qlog.to_dict()))
    (output / "early-reset-evidence.json").write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))


class Forward(asyncio.DatagramProtocol):
    def __init__(self, proxy, back=False):
        self.proxy, self.back = proxy, back

    def datagram_received(self, data, addr):
        p = self.proxy
        if self.back:
            p.front.sendto(data, p.client)
        else:
            p.client = addr
            p.back.sendto(data, ("127.0.0.1", 44433))


class NAT:
    """A real UDP relay changes the server-visible source port on demand."""
    async def start(self):
        self.front, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Forward(self), local_addr=("127.0.0.1", 0))
        self.back = None
        await self.rebind()
        return self.front.get_extra_info("sockname")[1]

    async def rebind(self):
        old = self.back
        self.back, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Forward(self, True), local_addr=("127.0.0.1", 0))
        if old:
            old.close()

    def close(self):
        self.front.close()
        self.back.close()


async def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    qlog = QuicLogger()
    with (output / "http3_lifecycle_aioquic.keys").open("w") as secrets:
        for version, number in [(1, 1), (0x6B3343CF, 2)]:
            for suite, name in [(CipherSuite.AES_128_GCM_SHA256, "aes128"),
                                (CipherSuite.AES_256_GCM_SHA384, "aes256"),
                                (CipherSuite.CHACHA20_POLY1305_SHA256, "chacha")]:
                tickets, received = {}, []
                server_config = QuicConfiguration(is_client=False, alpn_protocols=["h3"],
                    supported_versions=[version], cipher_suites=[suite], secrets_log_file=secrets, quic_logger=qlog)
                server_config.load_cert_chain(args.cert, args.key)
                proxy = NAT()
                port = await proxy.start()
                try:
                    for mode in ["seed", "accepted", "rejected"]:
                        if mode == "rejected":
                            tickets.clear()  # Reject resumption and retransmit early request at 1-RTT.
                        server = await serve("127.0.0.1", 44433, configuration=server_config,
                            create_protocol=HTTP, retry=(mode == "seed"), session_ticket_fetcher=tickets.get,
                            session_ticket_handler=lambda ticket: tickets.__setitem__(ticket.ticket, ticket))
                        config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE,
                            supported_versions=([0x6B3343CF, 1] if number == 1 and mode == "seed" else [version]),
                            cipher_suites=[suite], secrets_log_file=secrets, quic_logger=qlog,
                            session_ticket=(received[-1] if received and mode != "seed" else None))
                        async with connect("127.0.0.1", port, configuration=config, create_protocol=HTTP,
                                           session_ticket_handler=received.append, wait_connected=(mode == "seed")) as client:
                            await client.request(f"/v{number}/{name}/{mode}")
                            if mode == "seed":
                                await asyncio.sleep(0.05)
                                client._quic.change_connection_id()
                                await proxy.rebind()
                                await client.request(f"/v{number}/{name}/migrate")
                            await asyncio.sleep(0.05)
                            assert client.handshake.early_data_accepted == (mode == "accepted")
                            assert client._quic._version == version
                            assert client._quic.tls.key_schedule.cipher_suite == suite
                        server.close()
                        await asyncio.sleep(0.05)
                finally:
                    proxy.close()
                    server.close()
                await asyncio.sleep(0.05)
    (output / "lifecycle.qlog").write_text(json.dumps(qlog.to_dict()))
    (output / "lifecycle-evidence.json").write_text(json.dumps(HTTP.evidence, indent=2))
    print(json.dumps(HTTP.evidence, indent=2))


def independent_update(secret, version):
    """RFC 8446 HKDF label encoding, independently of aioquic's TLS helpers."""
    digest = hashlib.sha384 if len(secret) == 48 else hashlib.sha256
    label = b"tls13 " + (b"quicv2 ku" if version == 0x6B3343CF else b"quic ku")
    info = len(secret).to_bytes(2, "big") + bytes([len(label)]) + label + b"\x00"
    return hmac.new(secret, info + b"\x01", digest).digest()


def audit_sending_keys(peer):
    crypto = peer._quic._cryptos[Epoch.ONE_RTT].send
    encrypt = crypto.encrypt_packet
    original_hp, previous, generation = crypto.hp, crypto.secret, 0
    records = []

    def encrypt_checked(header, payload, packet_number):
        nonlocal previous, generation
        if crypto.secret != previous:
            assert crypto.secret == independent_update(previous, crypto.version)
            previous, generation = crypto.secret, generation + 1
        assert crypto.hp is original_hp
        assert (header[0] >> 2) & 1 == generation % 2
        packet = encrypt(header, payload, packet_number)
        pn_length = (header[0] & 3) + 1
        restored, _ = original_hp.remove(packet, len(header) - pn_length)
        assert restored == header
        records.append(dict(pn=packet_number, generation=generation, phase=generation % 2))
        return packet

    crypto.encrypt_packet = encrypt_checked
    return records


async def run_key_update_matrix(args):
    # aioquic 1.3.0 next_key_phase hardcodes the v1 update label. Adapt only
    # this generator run; its apply_key_phase already retains the original HP.
    import aioquic
    from aioquic.quic import crypto as quic_crypto
    assert aioquic.__version__ == "1.3.0"
    original_next = quic_crypto.next_key_phase

    def next_key_phase(current):
        if current.version != 0x6B3343CF:
            return original_next(current)
        algorithm = quic_crypto.cipher_suite_hash(current.cipher_suite)
        updated = quic_crypto.CryptoContext(key_phase=1-current.key_phase)
        updated.setup(cipher_suite=current.cipher_suite, version=current.version,
            secret=quic_crypto.hkdf_expand_label(algorithm, current.secret, b"quicv2 ku", b"", algorithm.digest_size))
        return updated

    quic_crypto.next_key_phase = next_key_phase
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    qlog, evidence = QuicLogger(), []
    try:
        with (output / "keyupdate-matrix.keys").open("w") as secrets:
            port = 44469
            for number, version in [(1, 1), (2, 0x6B3343CF)]:
                for name, suite in [("aes256", CipherSuite.AES_256_GCM_SHA384),
                                    ("chacha", CipherSuite.CHACHA20_POLY1305_SHA256)]:
                    start = len(EarlyResetHTTP.instances)
                    common = dict(alpn_protocols=["h3"], supported_versions=[version], cipher_suites=[suite],
                        secrets_log_file=secrets, quic_logger=qlog)
                    config = QuicConfiguration(is_client=False, **common)
                    config.load_cert_chain(args.cert, args.key)
                    server = await serve("127.0.0.1", port, configuration=config, create_protocol=EarlyResetHTTP)
                    try:
                        client_config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE, **common)
                        async with connect("127.0.0.1", port, configuration=client_config, create_protocol=EarlyResetHTTP) as client:
                            peers = [p for p in EarlyResetHTTP.instances[start:] if not p._quic.configuration.is_client]
                            assert len(peers) == 1
                            peer = peers[0]
                            records = [audit_sending_keys(client), audit_sending_keys(peer)]
                            assert client._quic._version == version
                            assert client._quic.tls.key_schedule.cipher_suite == suite
                            for generation in range(3):
                                if generation:
                                    initiator = client if generation == 1 else peer
                                    initiator._quic.request_key_update()
                                    await initiator.ping()
                                stream = await client.request(f"/ku/v{number}/{name}/g{generation}")
                                assert stream == generation * 4
                                await client.ping()
                                await peer.ping()
                                assert client._quic._handshake_confirmed and peer._quic._handshake_confirmed
                            for entries in records:
                                assert {e["generation"] for e in entries} == {0, 1, 2}
                                assert all(a["pn"] < b["pn"] for a, b in zip(entries, entries[1:]))
                            evidence.append(dict(version=hex(version), suite=suite.name, port=port,
                                client=records[0], server=records[1], v2_label_adapter=(number == 2)))
                    finally:
                        server.close()
                    port += 1
                    await asyncio.sleep(0.05)
    finally:
        quic_crypto.next_key_phase = original_next
    (output / "keyupdate-matrix.qlog").write_text(json.dumps(qlog.to_dict()))
    (output / "keyupdate-matrix-evidence.json").write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))


class RetryEarlyHTTP(EarlyResetHTTP):
    """Pinned aioquic 1.3.0 adapter: preserve TLS and requeue on valid Retry.

    Native _connect replaces TLS/packet spaces, changes ClientHello/early keys,
    and loses sent STREAM ranges. RFC 9000 section 17.2.5.3 requires the same
    handshake and early keys, with fresh packet numbers and new Initial keys.
    Native Retry integrity validation, loss callbacks and packet builders remain.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requeued_early = 0
        self.retry_preserved = False
        self.request_wire = b""
        transmit_original = self.transmit

        def transmit_checked():
            if self._quic.configuration.is_client and not self.request_wire:
                stream = self._quic._streams.get(0)
                if stream is not None and stream.sender._buffer:
                    assert stream.sender._buffer_start == 0
                    self.request_wire = bytes(stream.sender._buffer)
            return transmit_original()

        self.transmit = transmit_checked
        connect_original = self._quic._connect

        def connect_checked(now):
            quic = self._quic
            if not quic._retry_count:
                return connect_original(now)
            assert quic._is_client and not quic._handshake_complete
            handshake = bytes(quic._crypto_streams[Epoch.INITIAL].sender._buffer)
            early_secret = quic._cryptos[Epoch.ZERO_RTT].send.secret
            packet_number, tls = quic._packet_number, quic.tls
            assert handshake and early_secret
            assert bytes(quic._streams[0].sender._buffer) == self.request_wire
            assert quic._peer_cid.cid == quic._retry_source_connection_id
            assert quic._peer_token and quic._peer_cid.cid != quic._original_destination_connection_id
            for version, pair in quic._cryptos_initial.items():
                pair.setup_initial(cid=quic._peer_cid.cid, is_client=True, version=version)
            for epoch, space in quic._spaces.items():
                pending = tuple(space.sent_packets.values())
                if epoch == Epoch.ONE_RTT:
                    self.requeued_early += len(pending)
                quic._loss._on_packets_lost(now=now, packets=pending, space=space)
            assert bytes(quic._crypto_streams[Epoch.INITIAL].sender._buffer) == handshake
            assert quic._cryptos[Epoch.ZERO_RTT].send.secret == early_secret
            assert quic._packet_number == packet_number and quic.tls is tls
            self.retry_preserved = True

        self._quic._connect = connect_checked


async def run_retry_early(args):
    import aioquic
    assert aioquic.__version__ == "1.3.0"
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    qlog, evidence = QuicLogger(), []
    name = "retry-early-matrix" if args.retry_early_matrix else "retry-early"
    cells = [(1, 1, 44473, "", CipherSuite.AES_128_GCM_SHA256),
             (2, 0x6B3343CF, 44474, "", CipherSuite.AES_128_GCM_SHA256)]
    if args.retry_early_matrix:
        cells = [(number, version, 44478 + 2 * (number - 1) + index, suite_name, suite)
            for number, version in [(1, 1), (2, 0x6B3343CF)]
            for index, (suite_name, suite) in enumerate([
                ("aes256", CipherSuite.AES_256_GCM_SHA384),
                ("chacha", CipherSuite.CHACHA20_POLY1305_SHA256)])]
    with (output / (name + ".keys")).open("w") as secrets:
        for number, version, port, suite_name, suite in cells:
            tickets, received = {}, []
            common = dict(alpn_protocols=["h3"], supported_versions=[version], cipher_suites=[suite],
                secrets_log_file=secrets, quic_logger=qlog)
            config = QuicConfiguration(is_client=False, **common)
            config.load_cert_chain(args.cert, args.key)
            for mode in ["seed", "accepted", "rejected"]:
                if mode == "rejected":
                    tickets.clear()
                start = len(EarlyResetHTTP.instances)
                server = await serve("127.0.0.1", port, configuration=config, create_protocol=RetryEarlyHTTP,
                    retry=mode != "seed", session_ticket_fetcher=tickets.get,
                    session_ticket_handler=lambda ticket: tickets.__setitem__(ticket.ticket, ticket))
                try:
                    client_config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE,
                        session_ticket=received[-1] if mode != "seed" else None, **common)
                    async with connect("127.0.0.1", port, configuration=client_config, create_protocol=RetryEarlyHTTP,
                            session_ticket_handler=received.append, wait_connected=mode == "seed") as client:
                        path = f"/retry/v{number}/" + (suite_name + "/" if suite_name else "") + mode
                        assert await client.request(path) == 0
                        await asyncio.sleep(0.05)
                        assert client.handshake.early_data_accepted == (mode == "accepted")
                        assert client.handshake.session_resumed == (mode == "accepted")
                        assert client._quic._version == version
                        assert client._quic.tls.key_schedule.cipher_suite == suite
                        peer = [p for p in EarlyResetHTTP.instances[start:] if not p._quic.configuration.is_client]
                        assert len(peer) == 1 and peer[0].paths[0] == path.encode()
                        events = client._quic._quic_logger.to_dict()["events"]
                        retries = [i for i,e in enumerate(events) if e["name"] == "transport:packet_received" and
                            e["data"]["header"]["packet_type"] == "retry"]
                        sent = [dict(index=i, packet_type=e["data"]["header"]["packet_type"], **f)
                            for i,e in enumerate(events) if e["name"] == "transport:packet_sent"
                            for f in e["data"].get("frames", []) if f["frame_type"] == "stream" and f["stream_id"] == 0]
                        packet_numbers = [e["data"]["header"]["packet_number"] for e in events
                            if e["name"] == "transport:packet_sent"]
                        assert all(a < b for a, b in zip(packet_numbers, packet_numbers[1:]))
                        expected = ["1RTT"] if mode == "seed" else ["0RTT", "0RTT"]
                        if mode == "rejected":
                            expected.append("1RTT")
                        assert [f["packet_type"] for f in sent] == expected
                        assert all(f["offset"] == 0 and f["fin"] and
                            f["length"] == len(client.request_wire) for f in sent)
                        if not args.retry_early_matrix:
                            assert len(client.request_wire) == (26 if mode == "seed" else 29)
                        if mode == "seed":
                            assert not retries
                        else:
                            assert len(retries) == 1 and client.requeued_early > 0 and client.retry_preserved
                            assert any(f["packet_type"] == "0RTT" and f["index"] < retries[0] for f in sent)
                            assert any(f["packet_type"] == "0RTT" and f["index"] > retries[0] for f in sent)
                        evidence.append(dict(version=hex(version), mode=mode, path=path, port=port, suite=suite.name,
                            request_wire=client.request_wire.hex(),
                            early_accepted=client.handshake.early_data_accepted, retry_count=len(retries),
                            requeued_packets=client.requeued_early, preserved_handshake=client.retry_preserved, request_frames=sent))
                finally:
                    server.close()
                await asyncio.sleep(0.05)
    (output / (name + ".qlog")).write_text(json.dumps(qlog.to_dict()))
    (output / (name + "-evidence.json")).write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))


class DatagramPeer(QuicConnectionProtocol):
    """Independent RFC 9221 endpoint; no HTTP or stream framing."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = asyncio.Queue()
        self.handshake = None

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = event
        elif isinstance(event, DatagramFrameReceived):
            if self._quic.configuration.is_client:
                self.received.put_nowait(event.data)
            else:
                self._quic.send_datagram_frame(event.data)
                self.transmit()


async def run_datagram(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    qlog, evidence = QuicLogger(), []
    payloads = [b"", b"\x00\xffD11", b"repeat", b"repeat", b"tail"]
    early = b"early\x00\xff"
    with (output / "d11_datagram.keys").open("w") as secrets:
        for version, port in [(1, 44465), (0x6B3343CF, 44466)]:
            tickets, received = {}, []
            for mode in ["seed", "accepted", "rejected"]:
                if mode == "rejected":
                    tickets.clear()
                common = dict(alpn_protocols=["fixture-datagram"], supported_versions=[version],
                    cipher_suites=[CipherSuite.AES_128_GCM_SHA256], secrets_log_file=secrets,
                    quic_logger=qlog, max_datagram_frame_size=65535)
                config = QuicConfiguration(is_client=False, **common)
                config.load_cert_chain(args.cert, args.key)
                server = await serve("127.0.0.1", port, configuration=config, create_protocol=DatagramPeer,
                    session_ticket_fetcher=tickets.get,
                    session_ticket_handler=lambda ticket: tickets.__setitem__(ticket.ticket, ticket))
                config = QuicConfiguration(is_client=True, verify_mode=ssl.CERT_NONE,
                    session_ticket=received[-1] if mode != "seed" else None, **common)
                try:
                    async with connect("127.0.0.1", port, configuration=config, create_protocol=DatagramPeer,
                            session_ticket_handler=received.append, wait_connected=(mode == "seed")) as client:
                        if mode != "seed":
                            client._quic.send_datagram_frame(early)
                            client.transmit()
                            await client.wait_connected()
                        assert client.handshake.early_data_accepted == (mode == "accepted")
                        assert client._quic._version == version
                        assert client._quic.tls.key_schedule.cipher_suite == CipherSuite.AES_128_GCM_SHA256
                        # DATAGRAM is not retransmitted by QUIC. The application
                        # explicitly resends rejected early bytes as a new 1-RTT message.
                        if mode == "rejected":
                            client._quic.send_datagram_frame(early)
                        for payload in payloads:
                            client._quic.send_datagram_frame(payload)
                        client.transmit()
                        expected = ([early] if mode != "seed" else []) + payloads
                        actual = [await asyncio.wait_for(client.received.get(), 10) for _ in expected]
                        assert actual == expected, (mode, actual)
                        await asyncio.sleep(0.05)
                        assert client.received.empty()
                        assert received
                        evidence.append(dict(version=hex(version), mode=mode, suite="AES_128_GCM_SHA256",
                            resumed=client.handshake.session_resumed,
                            early_accepted=client.handshake.early_data_accepted,
                            responses=[x.hex() for x in actual]))
                finally:
                    server.close()
                await asyncio.sleep(0.05)
    (output / "datagram.qlog").write_text(json.dumps(qlog.to_dict()))
    (output / "datagram-evidence.json").write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--dynamic", action="store_true", help="generate the D05 dynamic QPACK/message fixture")
    parser.add_argument("--version", type=int, choices=[1, 2], default=1, help="QUIC version for --dynamic (default: 1)")
    parser.add_argument("--early-reset", action="store_true", help="generate v1/v2 accepted/rejected 0-RTT RESET fixtures")
    parser.add_argument("--datagram", action="store_true", help="generate the D11 QUIC DATAGRAM fixture")
    parser.add_argument("--key-update-matrix", action="store_true", help="generate v1/v2 AES256/ChaCha key updates")
    parser.add_argument("--retry-early", action="store_true", help="generate actual Retry with accepted/rejected 0-RTT")
    parser.add_argument("--retry-early-matrix", action="store_true", help="generate v1/v2 AES256/ChaCha Retry with 0-RTT")
    args = parser.parse_args()
    if sum([args.dynamic, args.datagram, args.early_reset, args.key_update_matrix, args.retry_early, args.retry_early_matrix]) > 1:
        parser.error("choose one fixture mode")
    asyncio.run(run_retry_early(args) if args.retry_early or args.retry_early_matrix else run_key_update_matrix(args) if args.key_update_matrix else run_datagram(args) if args.datagram else run_early_reset(args) if args.early_reset else run_dynamic(args) if args.dynamic else run(args))
