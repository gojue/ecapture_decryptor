# v1.4.4 (2026-11-13)

## Fixed

* Reclaim unused keylog secrets in long-running streaming APIs after connection workers finish draining, while protecting active TLS, QUIC, DTLS and nested TLS references. Expire unassociated secrets using `IdleTimeout` (default 5 minutes); newly admitted unresolved connections no longer keep old secrets indefinitely.
* Bound QUIC identity discovery by an absolute `KeyWaitTimeout` (default 30 seconds), including incomplete handshakes and Retry/version negotiation. Continued traffic or repeated DSBs do not renew the deadline; expiry reports `handshake/identity_timeout` and terminates the affected connection.
* Preserve legacy pcap input read errors instead of treating them as normal EOF, and correctly read non-seekable legacy pcap input after format detection.
* Drain available TLS stream-buffer data when a waiting read races with a write and close.

## Added

* Error categories supporting `errors.Is`: `ErrConnectionFailures`, `ErrPipelineFailure`, `ErrStreamCanceled` and `ErrEmitFailed`. Connection failures remain isolated during processing and are aggregated when the call ends; pipeline, callback and cancellation errors remain distinguishable and may coexist.
* Typed `crypto.KeyLogResourceLimitError` details for line length, entry count and secret-byte limits, exposing only resource names and counters while preserving `errors.Is(err, crypto.ErrKeyLogResourceLimit)`.

## Compatibility

* Existing Go entry-point signatures and options remain unchanged. File APIs retain keys for the entire call; lifecycle-based reclamation applies to `DecryptPcapngStream`, `DecryptPcapngStreamWithOptions` and `DecryptLiveTraffic`. New connections reusing retired or expired key identities must receive the secrets again.
* Keylog import limits, late-DSB handling and output backpressure remain enforced. Genuine capacity exhaustion still terminates the input pipeline rather than evicting required secrets. See the [API lifecycle and error contracts](docs/API.md#decryptpcapngstreamwithoptions--withoptions).

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.4.3...v1.4.4

<hr>

# v1.4.2 (2026-11-08)

## Added

* pcapng: preserve captured process arguments. See [PR #20](https://github.com/gojue/ecapture_decryptor/pull/20).

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.4.1...v1.4.2

<hr>

# v1.4.1 (2026-11-07)

## Fixed

* Route QUIC Initial packets with a zero-length client CID to the correct connection, retaining bidirectional routing on the unique original tuple. See [PR #18](https://github.com/gojue/ecapture_decryptor/pull/18).
* Preserve eCapture PID/Comm metadata from legacy and endpoint-tagged packet trailers in file and streaming decryption. Keep late metadata and loopback endpoint ownership in per-connection-generation state without changing routing keys or ConnectionID. See [PR #19](https://github.com/gojue/ecapture_decryptor/pull/19).
* Update C `GetVersion()` to v1.4.1.

## Compatibility

* Existing Go function signatures, C exports and `DecryptedPacket.PID` / `PName` fields remain available. Missing, malformed or conflicting process metadata remains unknown (`PID=0, PName=""`); the synthetic `decryptor` process name is no longer emitted. Explicit caller-provided process metadata is preserved.

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.4.0...v1.4.1

<hr>

# v1.4.0 (2026-11-07)

Changes since v1.3.2.

## Added

* QUIC v1/v2 directional Key Update for AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, with bounded previous-generation handling for reordered packets. Extend connection handling for CID rotation, migration, Retry, version negotiation and accepted/rejected 0-RTT.
* HTTP/3 dynamic QPACK, control streams, informational responses, trailers, push responses and RESET_STREAM handling.
* Opt-in `HTTPEvents` for incremental HTTP/1.x, HTTP/2 and HTTP/3 headers, body chunks, trailers and completion/reset events, plus SSE records and bounded optional gzip expansion. Incremental HTTP and raw QUIC streams can exceed 16 MiB without unbounded buffering.
* Validated bidirectional WebSocket fragmentation, control frames and negotiated permessage-deflate/context takeover. HTTP/2 gRPC message and status events in `HTTPEvents` mode support uncompressed/gzip messages while preserving opaque Protobuf bytes.
* Explicit Go `ApplicationProtocol` selection for DoT, DoH, DoQ, MQTT 3.1.1 and fixed-length Redis RESP2/RESP3, including DNS request/reply correlation, Redis pipelines and Pub/Sub.
* Explicit Go `TLSUpgrade` for SMTP, IMAP, POP3, LDAP, PostgreSQL/MySQL SSLRequest and HTTP/1 CONNECT, including one inner TLS layer through HTTPS CONNECT.
* TLS 1.3 directional KeyUpdate, fragmented handshake processing, HelloRetryRequest, session resumption, early-data handling and ECH decryption with matching keylog material. Cover HRR rejecting early data, ECH with HRR, and accepted ECH with HRR rejecting early data.
* QUIC DATAGRAM output preserving message boundaries in raw mode, and explicit Go `UDPProtocol: "dtls"` for DTLS 1.2 ECDHE-RSA AES-128/256-GCM application records with replay-window filtering.
* Independent real-capture regressions for these protocol states, including QUIC v1/v2 across all three TLS 1.3 suites for repeated bidirectional Key Update and Retry with accepted/rejected 0-RTT, plus TLS HRR/ECH/early-data combinations.

## Fixed

* Preserve QUIC early-stream ordering, partial prefixes and RESET state across late secrets and subsequent 1-RTT traffic.
* Retain TLS early records while secrets arrive, handle rejected early data using a different ticket cipher, and keep ECH early-secret lookup tied to the authenticated Inner random even when later traffic uses Outer random.
* Reject invalid TLS EndOfEarlyData transitions and avoid reporting successful decryption when no application candidate authenticates.
* Preserve WebSocket messages under backpressure and keep HTTP/3 informational/push responses separate from final responses in HAR export.
* Restore lint checks, validate and normalize release versions against the actual C API version string, and select explicit Docker target architectures. Align build instructions, Docker images and architecture documentation with Go 1.26 and the implemented APIs.
* Update C `GetVersion()` to v1.4.0; earlier v1.3.x tags retained the stale v1.2.0 string.

## Compatibility and scope

* Existing Go function signatures and C exports remain available. Zero-value options retain complete-message output and UDP defaults to QUIC. New output modes and protocol selectors are opt-in Go APIs; the CLI/C examples do not expose them. Use named fields in public option/secret struct literals because these structs have gained fields.
* Default message output gains WebSocket control and HTTP/3 informational/push kinds. Existing QUIC raw output gains DATAGRAM results with message boundaries and no stream offsets; consumers should distinguish `Metadata["kind"]`. Invalid option combinations and malformed protocol states can now fail explicitly.
* The module path, Go 1.26 baseline and dependencies are unchanged from v1.3.2. Release CI targets Linux amd64/arm64 and Darwin arm64.
* gRPC semantics cover HTTP/2 only. DNS covers ordinary queries, with DoQ limited to 1-RTT; MQTT covers 3.1.1; Redis excludes inline and streamed RESP. STARTTLS/tunnel parsing handles one negotiated upgrade. DTLS support is limited to the documented DTLS 1.2 suites and epoch, and does not add WebRTC or application decoding.
* ECH supports X25519/HKDF-SHA256/AES-128-GCM HPKE. Rejected ECH with HRR and early data, and cross-AEAD PSK resumption, still lack real-capture validation. Authentication here does not provide full certificate-chain/peer-identity verification or early-data replay protection.
* QUIC v2 Key Update and Retry/0-RTT fixtures use documented test-peer adapters; they do not establish unmodified-peer interoperability. See the [API contracts and evidence](docs/API.md) for key requirements, resource bounds, early-data output and unsupported states.

<hr>

# v1.3.2 (2026-11-04)

## Fixed

* Bound connection key waits and resource use with wall-clock timeouts, idle cleanup and connection limits; tighten cancellation and worker cleanup. See [PR #4](https://github.com/gojue/ecapture_decryptor/pull/4).

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.3.1...v1.3.2

<hr>

# v1.3.1 (2026-11-04)

## Fixed

* Retry buffered QUIC packets when late secrets arrive, including a DSB after the last network packet, without waiting for another packet or EOF. See [commit 513719a](https://github.com/gojue/ecapture_decryptor/commit/513719a).

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.3.0...v1.3.1

<hr>

# v1.3.0 (2026-11-04)

## Added

* Opt-in raw TLS/QUIC stream output and structured failure diagnostics through `DecryptPcapngStreamWithOptions` / `WithOptions`. See [PR #2](https://github.com/gojue/ecapture_decryptor/pull/2).

**Full Changelog**: https://github.com/gojue/ecapture_decryptor/compare/v1.2.0...v1.3.0

<hr>

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
