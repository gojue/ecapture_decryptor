# v1.1.0 (2026-10-19)

## What's Changed
* decryptor: stream pcapng secrets into complete HTTP/1.1 and HTTP/2 messages, including late DSBs, with replay tests and eCapture license updates by @cfc4n in https://github.com/cfc4n/ecapture_decryptor/pull/1

**Full Changelog**: https://github.com/cfc4n/ecapture_decryptor/compare/v1.0.0...a72fe584c4917b54216b25344d4200331a026068

<hr>

# v1.0.0

## What's Changed
* Decrypt TLS 1.2 and TLS 1.3 traffic over TCP from classic pcap data and NSS SSL key logs, with IPv4 and IPv6 support.
* Parse HTTP/1.x, HTTP/2, and WebSocket traffic into `DecryptedPacket` results with direction, timestamps, addresses, payloads, and protocol metadata.
* Use Go APIs for offline pcap files and caller-provided pcap streams, with configurable readers, output channel, and logger.
* Use C APIs for offline pcap files and pcap data from standard input; build static (`.a`) and shared (`.so`/`.dylib`) libraries with a C header.
* Run Go and C examples for decryption and export parsed traffic from the Go demo as JSON or HAR.

**Full Changelog**: https://github.com/cfc4n/ecapture_decryptor/commits/v1.0.0/

<hr>
