# TLS HTTP/1.x and HTTP/2 capture fixtures

The pcapng files in `test/testdata` contain real TCP packets captured on a
Linux VM. This program only generates TLS traffic; it never writes or modifies
packet headers. HTTP/1.0 here names the application protocol, not TLS 1.0;
all three clients negotiated TLS 1.3.

| Mode | Port | Scenario | tcpdump packets / DSB | eCapture packets / DSB |
| --- | ---: | --- | ---: | ---: |
| `http10` | 44434 | HTTP/1.0, close-delimited response | 16 / 0 | 30 / 4 |
| `http11` | 44435 | HTTP/1.1, two requests on one TCP connection, chunked request and response | 19 / 0 | 38 / 4 |
| `http2` | 44436 | HTTP/2, two overlapping request streams on one TCP connection | 24 / 0 | 48 / 4 |

Each mode has a `<name>_tcpdump_no_dsb.pcapng` file and matching
`<name>_tcpdump.keys` external SSLKEYLOG file, plus a
`<name>_ecapture_dsb.pcapng` file that embeds its keys. The names are `http10`,
`http11_keepalive_chunked`, and `http2_multiplex` respectively. All endpoints
are `127.0.0.1`; the certificate and keylog secrets are generated for these
isolated test requests, which contain no credentials or cookies.

Build on Linux with Go 1.26 from this directory:

```sh
go build -o http-tcp-traffic .
```

Start the server in one terminal and keep it running through the captures:

```sh
./http-tcp-traffic server
```

For each mode in the table, set `MODE`, `PORT`, and `NAME` in the capture
terminal. Start tcpdump before the client:

```sh
MODE=http11
PORT=44435
NAME=http11_keepalive_chunked
sudo timeout -s INT 7s tcpdump -i lo -s 0 -U -w "$NAME.pcap" "tcp port $PORT"
```

While tcpdump is running, use a second terminal in the same directory:

```sh
MODE=http11
NAME=http11_keepalive_chunked
SSLKEYLOGFILE="$PWD/${NAME}_tcpdump.keys" "$PWD/http-tcp-traffic" "$MODE"
```

After tcpdump exits, convert its packet capture to pcapng. `editcap` changes
the file format only; it does not synthesize packets or add a DSB:

```sh
editcap -F pcapng "$NAME.pcap" "${NAME}_tcpdump_no_dsb.pcapng"
```

For the DSB variant, set `ECAPTURE_BIN` to your built eCapture binary in the
capture terminal and run its Go TLS capture before the client:

```sh
TRAFFIC_BIN="$PWD/http-tcp-traffic"
sudo timeout -s INT 12s "$ECAPTURE_BIN" gotls -m pcap \
  -e "$TRAFFIC_BIN" -i lo \
  -w "$PWD/${NAME}_ecapture_dsb.pcapng" \
  -k "$PWD/${NAME}_ecapture_extra.keys" "tcp port $PORT"
```

Then run the client again in the other terminal:

```sh
SSLKEYLOGFILE="$PWD/${NAME}_ecapture_client.keys" "$PWD/http-tcp-traffic" "$MODE"
```

Repeat the commands for `http10:44434:http10` and
`http2:44436:http2_multiplex`. eCapture records both directions of loopback
packets; its captures contain duplicated TCP packets. The SDK tests use the
embedded DSB without either extra keylog file, verify one logical connection,
and assert all decrypted requests and responses.

## WebSocket and gRPC fixtures

`websocket_grpc.py` uses independent Python `websockets` and `hyper-h2` peers,
Python TLS and gzip. It imports no SDK or eCapture code. The committed captures
contain only loopback test messages, with matching `websocket_grpc.keys`:

- `websocket.pcapng`: 117 packets, two TLS connections on TCP 44437. Each sends
  three compressed fragmented messages in each direction, ping/pong and close.
  Context takeover is enabled on one connection and disabled on the other;
  both negotiate 12-bit sender windows. Peers verify exact text/binary bytes.
- `grpc_h2.pcapng`: 21 packets, one TLS/H2 connection on TCP 44438. Stream IDs
  1/3/5/7 exercise unary/client/server/bidi streaming, with eight request and
  eight response messages, mixed gzip/uncompressed messages, split prefixes,
  error trailers and a trailers-only error on stream 9. No descriptor is needed.

The combined capture had 138 packets and zero drops. `tshark` selects actual
captured packets by port, without synthesizing network traffic. Unit tests cover
malformed inputs, larger messages, resource bounds and backpressure separately.

Run in a fresh temporary directory; set `GENERATOR` to this repository's
`test/fixtures/http_tcp_capture/websocket_grpc.py`:

```sh
python3 -m venv venv
venv/bin/pip install websockets==15.0.1 h2==4.3.0 hpack==4.2.0 hyperframe==6.1.0
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout peer.key -out peer.crt -subj /CN=localhost -days 1
sudo dumpcap -i lo -B 64 -f 'tcp port 44437 or tcp port 44438' \
  -w - > combined.pcapng 2> capture.log &
CAPTURE_PID=$!
sleep 1
venv/bin/python "$GENERATOR" peer.crt peer.key websocket_grpc.keys
sleep 1
sudo kill -INT "$CAPTURE_PID"
wait "$CAPTURE_PID"
tshark -r combined.pcapng -Y 'tcp.port == 44437' -w websocket.pcapng
tshark -r combined.pcapng -Y 'tcp.port == 44438' -w grpc_h2.pcapng
```

The keylog must not already exist. Python writes real TLS secrets for these
isolated peers; keep certificate private keys out of the repository. From the
repository root, validate the committed fixtures with:

```sh
CGO_ENABLED=1 go test -race -run 'WebSocket|GRPC' ./protocol ./transport .
```

The SDK tests verify exact message bytes, stream/direction/connection identity,
status trailers, external keys, non-seekable input with tail DSB, and gRPC output
before capture EOF. This does not validate WebSocket extended CONNECT, gRPC-Web,
gRPC over HTTP/3 or compression algorithms other than gzip for gRPC.

## D08 MQTT and Redis fixtures

`d08_tcp.py` starts both TLS peers using only Python's standard library. It
checks every received wire byte and imports no SDK, eCapture or E01 code.
The matching external keylog for both captures is `d08_mqtt_redis.keys`.

| Capture | TCP port | Connections | Expected application messages |
| --- | ---: | ---: | --- |
| `d08_mqtt.pcapng` | 44440 | 1 | 20 MQTT 3.1.1 packets: CONNECT/CONNACK, subscribe, QoS 0/1/2, observed DUP, server publish, ping, unsubscribe and disconnect |
| `d08_redis.pcapng` | 44441 | 2 | 15 RESP2 + 13 RESP3 values: binary SET/GET pipeline, multi-channel pubsub and unsubscribe, HELLO 3, attribute and push before a pending GET reply |

From the repository root on Linux, with Python 3, OpenSSL, dumpcap and tshark
available, capture real loopback traffic before starting the peers:

```sh
work=$(mktemp -d)
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/peer.key" -out "$work/peer.crt" -subj /CN=localhost -days 1
sudo dumpcap -i lo -s 0 -B 64 -f 'tcp port 44440 or tcp port 44441' \
  -a duration:10 -w - > "$work/d08_tcp.pcapng" 2> "$work/capture.log" &
capture_pid=$!
sleep 1
python3 test/fixtures/http_tcp_capture/d08_tcp.py \
  "$work/peer.crt" "$work/peer.key" "$work/d08_mqtt_redis.keys"
wait "$capture_pid"
tshark -r "$work/d08_tcp.pcapng" -Y 'tcp.port == 44440' -w "$work/d08_mqtt.pcapng"
tshark -r "$work/d08_tcp.pcapng" -Y 'tcp.port == 44441' -w "$work/d08_redis.pcapng"
```

The keylog path must be new. An optional fourth argument, `mqtt` or `redis`,
runs just that protocol. Check `capture.log` for capture drops before using the
files; tshark only selects captured packets and does not manufacture traffic.
Keep the temporary certificate private key out of the repository. The peers
split length fields and payloads across TLS writes and coalesce application
messages; Redis values include NUL, CRLF and non-UTF-8 bytes. These captures
do not extend support to MQTT 5 or streamed RESP. Unit tests cover malformed
input, truncation, larger values, resource bounds and backpressure separately.

To validate the committed fixtures and protocol tests from the repository root:

```sh
CGO_ENABLED=1 go test -race -run 'TestD08ApplicationCaptureAPIs/(mqtt|redis)|TestMQTT|TestRedis' ./protocol .
```

The fixture regression verifies message counts, binary payloads, metadata and
connection identity with external keys and a non-seekable stream with a trailing
DSB. DNS fixture reproduction is in
[`../http3_capture/README.md`](../http3_capture/README.md#d08-dns-fixtures).

## D09 TLS upgrade and CONNECT fixtures

`tls_upgrade.py` uses Python's standard-library sockets, TLS and MemoryBIO to
generate real loopback traffic. It imports no SDK, eCapture or E01 code and
never writes capture packets. Every mode opens two connections: a refused
negotiation followed by a separate successful negotiation. The refused peer
continues with fixed plaintext containing a fake TLS record prefix; it never
retries an upgrade on that connection.

| Mode / capture name | TCP port | Upgrade boundary |
| --- | ---: | --- |
| `smtp` / `d09_smtp.pcapng` | 44446 | EHLO capabilities, STARTTLS, 220 success / 454 refusal |
| `imap` / `d09_imap.pcapng` | 44447 | CAPABILITY, tagged STARTTLS, matching tagged OK / NO |
| `pop3` / `d09_pop3.pcapng` | 44448 | CAPA, STLS, +OK / -ERR |
| `ldap` / `d09_ldap.pcapng` | 44449 | BER StartTLS extended request, result code 0 / 52 |
| `postgres` / `d09_postgres.pcapng` | 44450 | Eight-byte SSLRequest, S / N |
| `mysql` / `d09_mysql.pcapng` | 44451 | Protocol 10 greeting with / without CLIENT_SSL; successful client sends a 32-byte SSLRequest |
| `connect` / `d09_connect.pcapng` | 44452 | Plain HTTP/1.1 CONNECT, 200 / 407 |
| `https_connect` / `d09_https_connect.pcapng` | 44453 | CONNECT inside outer TLS, then independent inner TLS on success |

The committed captures were generated with Python 3.14.4, OpenSSL 3.5.5 and
Wireshark/dumpcap 4.6.4 on Linux arm64 (506 packets, zero drops).
All TLS layers negotiate TLS 1.3 and ALPN `http/1.1`. Successful upgrades
exchange exactly one HTTP/1.1 POST to `/d09/MODE` and one 200 response. Their
bodies are `d09/MODE/request` and `d09/MODE/response`, each followed by the
bytes `00 0d 0a ff`. This deliberately tests TLS handoff and HTTP/raw output;
it does not implement encrypted mail, LDAP or database application semantics.
Prelude and payload writes are fragmented. MySQL's SSLRequest tail and the
actual TLS ClientHello share one socket write. Other clients wait for the
successful upgrade response before starting TLS, preserving protocol ordering.

`d09_upgrade.keys` contains the ordinary upgrade secrets and HTTPS CONNECT's
outer TLS secrets. Only `d09_inner.keys` contains HTTPS CONNECT's inner TLS
secrets, allowing separate complete-key and missing-inner-key regressions.
Both paths must be new. Inner TLS runs over an outer SSLObject and actual TCP;
the nested traffic is not assembled from synthetic encrypted capture records.

Run from the repository root on Linux with Python 3 linked to a TLS 1.3-capable
OpenSSL, plus OpenSSL CLI, dumpcap and tshark:

```sh
work=$(mktemp -d)
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/peer.key" -out "$work/peer.crt" -subj /CN=localhost -days 1
sudo -v
sudo -n dumpcap -i lo -s 0 -B 64 -f 'tcp portrange 44446-44453' \
  -w - > "$work/d09_all.pcapng" 2> "$work/capture.log" &
capture_pid=$!
trap 'sudo -n kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true' EXIT
sleep 1
python3 test/fixtures/http_tcp_capture/tls_upgrade.py \
  --cert "$work/peer.crt" --key "$work/peer.key" \
  --keylog "$work/d09_upgrade.keys" --inner-keylog "$work/d09_inner.keys" \
  --mode all > "$work/evidence.jsonl"
# Let the capture queue drain after the final TLS close_notify/TCP close.
sleep 1
sudo -n kill -INT "$capture_pid"
wait "$capture_pid"
trap - EXIT
for entry in smtp:44446 imap:44447 pop3:44448 ldap:44449 postgres:44450 mysql:44451 connect:44452 https_connect:44453; do
  mode=${entry%:*}
  port=${entry##*:}
  tshark -r "$work/d09_all.pcapng" -Y "tcp.port == $port" -w "$work/d09_$mode.pcapng"
done
```

`--mode` can select any single mode in the table. Check capture drops in
`capture.log` and the eight successful peer summaries in `evidence.jsonl`
before using a full run. Each summary includes SHA-256 hashes of the complete
expected HTTP request and response; both peers also verify every received byte
and exchange TLS close_notify. Keep temporary certificate private keys out of
Git. Tshark only filters real captured packets by port.

The negotiation transcripts follow [SMTP STARTTLS](https://www.rfc-editor.org/rfc/rfc3207.html),
[IMAP/POP3 TLS](https://www.rfc-editor.org/rfc/rfc2595.html),
[LDAP StartTLS](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.14),
[PostgreSQL SSLRequest](https://www.postgresql.org/docs/18/protocol-flow.html#PROTOCOL-FLOW-SSL),
[MySQL SSLRequest](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_ssl_request.html)
and [HTTP CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).

## D10 TLS state fixtures

`tls_d10_openssl.c` and `tls_d10_ech.go` are standalone peers, independent of
the SDK and eCapture. Both are excluded from ordinary Go package builds and
must be compiled explicitly. The C peer uses OpenSSL's public APIs and real
TCP sockets; the Go peer uses Go 1.26 `crypto/tls` and `crypto/ecdh`. Neither
program writes capture files or synthesizes encrypted network records.

The Go ECH pair was captured in 31 packets with zero drops.
The OpenSSL matrix was captured with OpenSSL **3.5.5** on the Linux VM: 308
packets and zero reported drops. Endpoint assertions verify actual negotiated
ciphers, resumed sessions, early-data status and sent handshake messages.
The two Go ECH modes also assert accepted/rejected outcomes independently.

| Mode / `d10_MODE.pcapng` | TCP port | Connections / HTTP exchanges | Scope |
| --- | ---: | --- | --- |
| `ku_aes128` | 44454 | 1 / 6 | TLS 1.3 AES-128-GCM/SHA256, three KeyUpdates per direction |
| `ku_aes256` | 44455 | 1 / 6 | TLS 1.3 AES-256-GCM/SHA384, three KeyUpdates per direction |
| `ku_chacha` | 44456 | 1 / 6 | TLS 1.3 ChaCha20-Poly1305/SHA256, three KeyUpdates per direction |
| `hrr` | 44457 | 1 / 1 | TLS 1.3 AES-128-GCM, client X25519 first share, server P-256; one actual HRR |
| `early` | 44458 | 4 / 4 | TLS 1.3 AES-128-GCM seed, ordinary resumption, accepted early data, rejected early data |
| `tls12_resume` | 44459 | 2 / 2 | TLS 1.2 ECDHE-RSA-AES256-GCM-SHA384, seed and resumed session |
| `ech_accepted` | 44460 | 1 / 1 | Go TLS 1.3 AES-128-GCM; accepted X25519/HKDF-SHA256/AES-128-GCM ECH |
| `ech_rejected` | 44461 | 1 / 0 | Different server ECH configuration; expected ECHRejectionError and retry config, no application data |
| `grease` | 44462 | 1 / 1 | OpenSSL TLS 1.3 AES-128-GCM, opaque GREASE-style ECH extension, ordinary outer handshake |

Each successful HTTP exchange has an exact request:
`GET /d10/MODE/INDEX HTTP/1.1\r\nHost: fixture\r\n\r\n`.
Its response is `HTTP/1.1 200 OK\r\nContent-Length: N\r\n\r\n` followed by
`d10/MODE/INDEX\n`, where N is that body's byte length. KeyUpdate indices are
0 through 5 on one connection; other indices identify the connection, starting
at 0. Writes split the first three HTTP bytes into a separate TLS record.
No mail/database semantics or external service is involved.

The C message callback records actual outgoing KeyUpdates, including one
`update_requested` and two `update_not_requested` messages in each direction.
Both peers check every HTTP byte after the updates. The HRR callback compares
the complete reserved ServerHello random. Early-data connection 2 is accepted
and sends EndOfEarlyData; connection 3 is rejected and retransmits the same
request at 1-RTT. Connections 1, 2 and 3 all assert session reuse. The fixture
does not disable OpenSSL anti-replay protection or claim TLS 1.2 renegotiation.

`d10_openssl.keys` contains the seven C modes' real OpenSSL keylog callbacks,
including handshake, application and client early traffic secrets.
`d10_ech.keys` contains Go's normal keylog output plus RFC 9850 `ECH_SECRET`
and `ECH_CONFIG`. Go 1.26 does not log those two labels itself: a read-only
connection observer extracts the actual outer random and encapsulated key,
then derives DHKEM's shared secret using the generator-owned X25519 private
key and standard HKDF. The logged config is one complete ECHConfig, not an
ECHConfigList. ECH labels use OuterRandom; accepted TLS traffic labels use
InnerRandom. The observer never alters transmitted bytes. These original captures
do not include HRR combinations; the separate fixtures below add them.

Reproduce from the repository root on Linux with Go 1.26, a C compiler,
OpenSSL development headers, pkg-config, OpenSSL CLI, dumpcap and tshark:

```sh
work=$(mktemp -d)
umask 077
cc -Wall -Wextra -Werror test/fixtures/http_tcp_capture/tls_d10_openssl.c \
  -o "$work/tls-d10-openssl" $(pkg-config --cflags --libs openssl) -lpthread
go build -o "$work/tls-d10-ech" test/fixtures/http_tcp_capture/tls_d10_ech.go
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/peer.key" \
  -out "$work/peer.crt" -days 1 -subj /CN=localhost
sudo -v
sudo -n dumpcap -i lo -s 0 -B 64 -f 'tcp portrange 44454-44462 or tcp port 44475' \
  -w - > "$work/d10_all.pcapng" 2> "$work/capture.log" &
capture_pid=$!
trap 'sudo -n kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true' EXIT
sleep 1
"$work/tls-d10-openssl" "$work/peer.crt" "$work/peer.key" "$work/d10_openssl.keys" all \
  > "$work/openssl-evidence.jsonl"
"$work/tls-d10-ech" --cert "$work/peer.crt" --key "$work/peer.key" \
  --keylog "$work/d10_ech.keys" --mode all > "$work/ech-evidence.jsonl"
sleep 1
sudo -n kill -INT "$capture_pid"
wait "$capture_pid"
trap - EXIT
for entry in ku_aes128:44454 ku_aes256:44455 ku_chacha:44456 hrr:44457 early:44458 tls12_resume:44459 ech_accepted:44460 ech_rejected:44461 grease:44462 hrr_early:44475; do
  mode=${entry%:*}
  port=${entry##*:}
  tshark -r "$work/d10_all.pcapng" -Y "tcp.port == $port" -w "$work/d10_$mode.pcapng"
done
```

Every keylog path must be new. The C program's final argument may select any
single C mode; the Go program accepts `--mode accepted` or `--mode rejected`.
Inspect peer evidence and capture drops before replacing fixtures, and allow
the final close_notify/FIN/ACK traffic to drain before stopping capture. Keep
certificate private keys and local evidence files out of Git. The SDK's
missing-key, wrong-key, record-tampering and fragmented-handshake regressions
are separate from this real-traffic matrix. References:
[OpenSSL KeyUpdate](https://docs.openssl.org/3.5/man3/SSL_key_update/),
[OpenSSL early data](https://docs.openssl.org/3.5/man3/SSL_read_early_data/) and
[RFC 9850 ECH keylog labels](https://www.rfc-editor.org/rfc/rfc9850.html#section-2.3).

### HRR with early data and ECH

Separate captures generated by the same OpenSSL 3.5.5 and Go 1.26 peers contain
81 real loopback packets with zero drops. All negotiate TLS_AES_128_GCM_SHA256.
The SDK is not imported by either peer and does not generate these packets.

| Capture basename | TCP port | Packets | Independent endpoint assertions |
| --- | ---: | ---: | --- |
| `d10_hrr_early` | 44475 | 39 | Seed plus early attempt: server switches from X25519 to P-256; one HRR, two ClientHellos, only CH1 offers early data, rejected early, no EndOfEarlyData, exact request retransmitted at 1-RTT |
| `d10_ech_hrr_accepted` | 44476 | 24 | One HRR and two ClientHellos; ECH accepted by both Go peers, CH2 enc length zero, exact HTTP exchange |
| `d10_ech_hrr_rejected` | 44477 | 18 | One HRR and two ClientHellos; expected ECHRejectionError/retry config, CH2 retains original 32-byte enc, no application data |

The early attempt uses a real seed ticket, but OpenSSL selects a full handshake
after HRR (`session_reused=0`); this is not evidence of PSK resumption after HRR.
The server's early-data callback allows the attempt: rejection is forced by HRR,
not by the fixture callback. Request indices are 0 and 1. The ECH paths use
`/d10/ech_hrr_accepted/0` and the same HTTP format as above. The wire observer
counts actual ClientHello/HRR messages and records CH2's enc length; it never
rewrites the connection. These captures do not cover ECH+HRR+early together.

`d10_hrr_early.keys` comes from the OpenSSL callback;
`d10_ech_hrr.keys` contains Go traffic secrets plus the observed CH1 OuterRandom's
RFC 9850 ECH material. Certificate private keys and local JSON evidence stay out
of Git. Reuse the compiler/Go setup and ephemeral certificate above, then run a
separate capture (the C mode is explicit; `--hrr` defaults off for the Go peer):

```sh
sudo -n dumpcap -i lo -s 0 -B 64 -f 'tcp portrange 44475-44477' -w - \
  > "$work/hrr-all.pcapng" 2> "$work/hrr-capture.log" &
capture_pid=$!
trap 'sudo -n kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true' EXIT
sleep 1
"$work/tls-d10-openssl" "$work/peer.crt" "$work/peer.key" \
  "$work/d10_hrr_early.keys" hrr_early > "$work/hrr-early-evidence.jsonl"
"$work/tls-d10-ech" --cert "$work/peer.crt" --key "$work/peer.key" \
  --keylog "$work/d10_ech_hrr.keys" --hrr > "$work/ech-hrr-evidence.jsonl"
sleep 1
sudo -n kill -INT "$capture_pid"
wait "$capture_pid"
trap - EXIT
for entry in hrr_early:44475 ech_hrr_accepted:44476 ech_hrr_rejected:44477; do
  mode=${entry%:*}
  port=${entry##*:}
  tshark -r "$work/hrr-all.pcapng" -Y "tcp.port == $port" -w "$work/d10_$mode.pcapng"
done
go test -race -run '^TestD10TLSCapture(APIs|InvalidSecrets)$' -v .
```

The API matrix checks exact messages/raw bytes/HTTPEvents, external keys and
trailing DSB, opposite early/handshake-secret arrival orders, delivery before
EOF, duplicate DSBs and missing/wrong ECH associations. State tests complement
real captures with bad HRR/final confirmations, altered CH2 payload/AAD/enc,
repeated HRR, forbidden early/EOED boundaries, limits and key-wait deadlines.

## D11 DTLS 1.2 fixtures

`dtls_capture.c` is a separate, build-excluded OpenSSL UDP peer because DTLS
requires datagram BIOs and handshake fragmentation rather than the TCP fixture's
stream transport. It links no SDK code and produces only real loopback traffic.
The committed captures were generated with OpenSSL **3.5.5**: 36 packets total,
zero reported drops, and 18 packets in each capture.

| Capture | UDP port | Negotiated DTLS 1.2 suite |
| --- | ---: | --- |
| `d11_dtls_aes128.pcapng` | 44463 | ECDHE-RSA-AES128-GCM-SHA256 (`0xc02f`) |
| `d11_dtls_aes256.pcapng` | 44464 | ECDHE-RSA-AES256-GCM-SHA384 (`0xc030`) |

Each capture contains one connection, one HelloVerifyRequest/cookie exchange,
and four non-complete handshake fragments produced with MTU 512. Record headers
use `0xfeff` during the initial exchange and `0xfefd` for DTLS 1.2; ServerHello
negotiates `0xfefd`. The fixture's fixed cookie is local test data, not an example
of production address-bound cookie protection.

Each peer sends four application records with identical content but distinct
record sequences: epoch 1, sequence 1 through 4. Client payloads are exactly
`dtls request\x00\xff\r\n` (16 bytes); server payloads are exactly
`dtls response\x00\xfe\r\n` (17 bytes). Every SSL read checks the entire datagram
and its length. Repeated plaintext is intentional application repetition, not
record retransmission. `d11_dtls.keys` contains two real `CLIENT_RANDOM` entries,
each with a 48-byte master secret from the client keylog callback. Independent
standard-library PRF/AES-GCM decoding also verified all 16 application records
against these fixed byte strings.

OpenSSL 3.5.5 did not emit an application record for a zero-length write; empty
records, reordered/retransmitted packets and malformed-input behavior therefore
need separate SDK state tests. These captures do not claim DTLS 1.3, CID,
resumption, renegotiation, SRTP, SCTP, CoAP or WebRTC coverage.

Reproduce from the repository root on Linux with OpenSSL development headers,
pkg-config, a C compiler, OpenSSL CLI, timeout, dumpcap and tshark:

```sh
work=$(mktemp -d)
umask 077
cc -Wall -Wextra -Werror test/fixtures/http_tcp_capture/dtls_capture.c \
  -o "$work/dtls-peer" $(pkg-config --cflags --libs openssl) -lpthread
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/peer.key" \
  -out "$work/peer.crt" -days 1 -subj /CN=localhost
sudo -v
sudo -n dumpcap -i lo -s 0 -B 64 -f 'udp portrange 44463-44464' \
  -w - > "$work/d11_dtls_all.pcapng" 2> "$work/capture.log" &
capture_pid=$!
trap 'sudo -n kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true' EXIT
sleep 1
timeout 20 "$work/dtls-peer" "$work/peer.crt" "$work/peer.key" \
  "$work/d11_dtls.keys" all > "$work/evidence.jsonl"
sleep 1
sudo -n kill -INT "$capture_pid"
wait "$capture_pid"
trap - EXIT
for entry in aes128:44463 aes256:44464; do
  mode=${entry%:*}
  port=${entry##*:}
  tshark -r "$work/d11_dtls_all.pcapng" -Y "udp.port == $port" \
    -w "$work/d11_dtls_$mode.pcapng"
done
```

The keylog path must be new; the final peer argument may select `aes128` or
`aes256` instead of `all`. Check the endpoint evidence and capture drop counts
before replacing fixtures. Keep the certificate private key and local evidence
outside Git. References: [OpenSSL datagram BIO](https://docs.openssl.org/3.5/man3/BIO_s_datagram/)
and [DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347.html).
