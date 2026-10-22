# v1.2.0 (2026-10-22)

## What's Changed
* Decrypt QUIC v1 traffic from UDP captures and reconstruct HTTP/3 requests and responses as `DecryptedPacket` results.
* Load TLS secrets from an external SSLKEYLOG, pcapng Decryption Secrets Blocks (DSBs), or both; allow pcapng decryption without a separate key log in the Go and C APIs and examples.
* Improve HAR export by pairing HTTP/2 and HTTP/3 messages by stream ID, producing HTTPS URLs, and handling gzip and binary response bodies.
* Add real pcapng fixtures and integration tests for HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 with external key logs and embedded DSBs.
* Change the Go module path from `github.com/cfc4n/ecapture_decryptor` to `github.com/gojue/ecapture_decryptor`; consumers must update their imports.

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.1.0...8b659be74e1bdac43e72848506f593ced7ff44e2

<hr>

# v1.1.0 (2026-10-19)

## What's Changed
* decryptor: stream pcapng secrets into complete HTTP/1.1 and HTTP/2 messages, including late DSBs, with replay tests and eCapture license updates by @cfc4n in https://github.com/gojue/ecapture_decryptor/pull/1

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.0.0...a72fe584c4917b54216b25344d4200331a026068

<hr>

# v1.0.0

## What's Changed
* Decrypt TLS 1.2 and TLS 1.3 traffic over TCP from classic pcap data and NSS SSL key logs, with IPv4 and IPv6 support.
* Parse HTTP/1.x, HTTP/2, and WebSocket traffic into `DecryptedPacket` results with direction, timestamps, addresses, payloads, and protocol metadata.
* Use Go APIs for offline pcap files and caller-provided pcap streams, with configurable readers, output channel, and logger.
* Use C APIs for offline pcap files and pcap data from standard input; build static (`.a`) and shared (`.so`/`.dylib`) libraries with a C header.
* Run Go and C examples for decryption and export parsed traffic from the Go demo as JSON or HAR.

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/commits/v1.0.0/

<hr>
