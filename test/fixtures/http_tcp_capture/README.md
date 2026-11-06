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
