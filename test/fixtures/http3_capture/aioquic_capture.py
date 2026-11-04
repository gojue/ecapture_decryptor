#!/usr/bin/env python3
"""Generate independent QUIC lifecycle traffic (aioquic 1.3.0).

Capture real loopback UDP port 44433 separately; this program never writes pcap.
Usage: python aioquic_capture.py --cert cert.pem --key key.pem --output DIR
"""
# Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
# See LICENSE for the applicable license.
import argparse
import asyncio
import json
import ssl
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicLogger
from aioquic.tls import CipherSuite


class StaticH3(H3Connection):
    def _get_local_settings(self):
        settings = super()._get_local_settings()
        settings[Setting.QPACK_MAX_TABLE_CAPACITY] = 0
        settings[Setting.QPACK_BLOCKED_STREAMS] = 0
        return settings


class HTTP(QuicConnectionProtocol):
    evidence = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = StaticH3(self._quic)
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output", required=True)
    asyncio.run(run(parser.parse_args()))
