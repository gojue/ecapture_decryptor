# HTTP/3 Linux capture fixtures

These pcapng fixtures contain real UDP packets captured on a Linux VM. The Go
program in this directory generates HTTP/3 traffic; it does not write pcapng
files or synthesize packet headers. The checked-in fixtures cover two targets:

| Target | Capture tool | Fixture | Packet blocks | DSB blocks |
| --- | --- | --- | ---: | ---: |
| `127.0.0.1:44433` | tcpdump | `http3_loopback_tcpdump_no_dsb.pcapng` | 23 | 0 |
| `127.0.0.1:44433` | eCapture | `http3_loopback_ecapture_dsb.pcapng` | 50 | 4 |
| `www.cloudflare.com:443` | tcpdump | `http3_cloudflare_tcpdump_no_dsb.pcapng` | 46 | 0 |
| `www.cloudflare.com:443` | eCapture | `http3_cloudflare_ecapture_dsb.pcapng` | 39 | 4 |

The loopback client sends `GET /one` and a `POST /upload` with a 2,400-byte
body over one QUIC connection. The public client requests `/robots.txt` and
`/favicon.ico` over one connection with normal certificate verification. Both
public resources returned HTTP/3 200 when captured. The client sends no
credentials or cookies. All four captures were taken with
`QUIC_GO_DISABLE_GSO=true`; otherwise Linux UDP GSO can put multiple QUIC
segments into one capture record.

Build the traffic program on Linux with Go 1.26:

```sh
go build -o http3-traffic .
```

## Local target: `127.0.0.1:44433`

Start the server in one terminal and leave it running for both captures:

```sh
QUIC_GO_DISABLE_GSO=true ./http3-traffic server 44433
```

For the external-keylog fixture, start tcpdump in a second terminal:

```sh
sudo timeout -s INT 8s tcpdump -i lo -s 0 -U \
  -w http3_loopback_tcpdump.pcap 'udp port 44433'
```

While tcpdump is running, use a third terminal for the client:

```sh
SSLKEYLOGFILE="$PWD/http3_loopback_tcpdump.keys" QUIC_GO_DISABLE_GSO=true \
  ./http3-traffic client 44433
```

After tcpdump exits, convert its actual capture to pcapng. `editcap` changes
only the file container; it does not create packets or add a DSB:

```sh
editcap -F pcapng http3_loopback_tcpdump.pcap http3_loopback_tcpdump_no_dsb.pcapng
```

For the embedded-DSB fixture, set `ECAPTURE_BIN` to your built eCapture
binary. With the server still running, start eCapture in the second terminal:

```sh
sudo timeout -s INT 13s "$ECAPTURE_BIN" gotls -m pcap \
  -e "$PWD/http3-traffic" -i lo \
  -w "$PWD/http3_loopback_ecapture_dsb.pcapng" \
  -k "$PWD/loopback_ecapture_extra.keys" 'udp port 44433'
```

Then run the client in the third terminal:

```sh
SSLKEYLOGFILE="$PWD/loopback_ecapture_client.keys" QUIC_GO_DISABLE_GSO=true \
  ./http3-traffic client 44433
```

## Public target: `www.cloudflare.com:443`

Find the VM's egress interface with `ip route get 1.1.1.1` and assign its name
to `WAN_IF`. The domain's IP address can change between runs. Capture UDP/443
on that interface while running the public client.

For the external-keylog fixture, start tcpdump:

```sh
sudo timeout -s INT 8s tcpdump -i "$WAN_IF" -s 0 -U \
  -w http3_cloudflare_tcpdump.pcap 'udp port 443'
```

In another terminal, run the client while tcpdump is active:

```sh
SSLKEYLOGFILE="$PWD/http3_cloudflare_tcpdump.keys" QUIC_GO_DISABLE_GSO=true \
  ./http3-traffic client-url https://www.cloudflare.com
```

After tcpdump exits, convert the capture to pcapng:

```sh
editcap -F pcapng http3_cloudflare_tcpdump.pcap http3_cloudflare_tcpdump_no_dsb.pcapng
```

For the embedded-DSB fixture, start eCapture:

```sh
sudo timeout -s INT 15s "$ECAPTURE_BIN" gotls -m pcap \
  -e "$PWD/http3-traffic" -i "$WAN_IF" \
  -w "$PWD/http3_cloudflare_ecapture_dsb.pcapng" \
  -k "$PWD/cloudflare_ecapture_extra.keys" 'udp port 443'
```

Then run the public client again:

```sh
SSLKEYLOGFILE="$PWD/cloudflare_ecapture_client.keys" QUIC_GO_DISABLE_GSO=true \
  ./http3-traffic client-url https://www.cloudflare.com
```

The two tcpdump fixtures use their matching checked-in NSS SSLKEYLOG files.
The eCapture fixtures embed the Go TLS secrets as DSB blocks, so the SDK tests
do not use their separate keylog files. eCapture may record both directions of
loopback packets; the SDK test checks that each HTTP/3 message is emitted once.

## Key Update fixtures

`http3_keyupdate_v{1,2}.pcapng` and their matching `.keys` files were generated
independently of eCapture on Linux ARM64 with Go 1.26.0, quic-go v0.59.1 and
`dumpcap` on loopback. They contain 12 POSTs to `/update/0` through `/update/11`,
each with `"payload-"` repeated 300 times. Each response is exactly
`"POST /update/N " + requestBody`. ALPN is `h3`; ServerHello in both captures
selects `TLS_AES_128_GCM_SHA256` (`0x1301`). Wire versions are `0x00000001` and
`0x6b3343cf`. There are 148 / 144 captured packets respectively, with no capture
drops. No external service, probe or private capture is needed.

The generator now selects v1 by default, accepts `QUIC_VERSION=1|2`, and has a
`client-updates` workload. It writes endpoint qlogs when `QLOGDIR` is set.
The SDK tests compare bodies and header metadata semantically, raw bytes
exactly, and replay both external keys and late DSBs without waiting for EOF.

For compact fixtures, the **temporary generator dependency copy** changes
`FirstKeyUpdateInterval` from 100 to 10 and `KeyUpdateInterval` from 100000 to
10. This leaves real UDP, TLS, packet protection, acknowledgments and stream
handling in quic-go. The module cache and both checked-in `go.mod` files stay
unchanged.

A separate generator defect was found during this validation: quic-go v0.59.1
`internal/handshake/updatable_aead.go:getNextTrafficSecret` always uses
`quic ku`, including v2. The uncorrected v2 capture failed at its first update.
The temporary copy used for the committed v2 fixture selects `quicv2 ku` for
v2, as required by [RFC 9369 §3.3.2](https://www.rfc-editor.org/rfc/rfc9369.html#section-3.3.2).
The SDK does not accept the incorrect label as a fallback. The v1 fixture
needs only the interval changes. These are explicitly patched quic-go capture
results, not claims of unmodified quic-go v2 interoperability.

To reproduce, run from this directory, using Go 1.26 and an installed dumpcap:

```sh
export GOWORK=off
export FIXTURE_TMP="$(mktemp -d)"
go mod download
cp go.mod "$FIXTURE_TMP/fixture.mod"
cp go.sum "$FIXTURE_TMP/fixture.sum"
python3 - <<'PY'
import os, pathlib, shutil, subprocess
root = pathlib.Path(os.environ["FIXTURE_TMP"])
source = subprocess.check_output(
    ["go", "list", "-m", "-f", "{{.Dir}}", "github.com/quic-go/quic-go"], text=True).strip()
copy = root / "quic-go"
shutil.copytree(source, copy)
p = copy / "internal/handshake/updatable_aead.go"
p.chmod(0o644)
s = p.read_text().replace("var FirstKeyUpdateInterval uint64 = 100",
                          "var FirstKeyUpdateInterval uint64 = 10")
old = 'return hkdfExpandLabel(hash, ts, []byte{}, "quic ku", hash.Size())'
assert old in s
s = s.replace(old, '''label := "quic ku"
    if a.version == protocol.Version2 { label = "quicv2 ku" }
    return hkdfExpandLabel(hash, ts, []byte{}, label, hash.Size())''')
p.write_text(s)
p = copy / "internal/protocol/params.go"
p.chmod(0o644)
p.write_text(p.read_text().replace("const KeyUpdateInterval = 100 * 1000",
                                   "const KeyUpdateInterval = 10"))
PY
go mod edit -modfile="$FIXTURE_TMP/fixture.mod" \
  -replace "github.com/quic-go/quic-go=$FIXTURE_TMP/quic-go"
go build -modfile="$FIXTURE_TMP/fixture.mod" -o "$FIXTURE_TMP/http3-traffic" .

for version in 1 2; do
  export QUIC_VERSION="$version" QUIC_GO_DISABLE_GSO=true
  export QLOGDIR="$FIXTURE_TMP/qlog-v$version"
  mkdir "$QLOGDIR"
  "$FIXTURE_TMP/http3-traffic" server 44433 > "$FIXTURE_TMP/server-v$version.log" 2>&1 &
  server_pid=$!
  sudo dumpcap -i lo -f 'udp port 44433' -a duration:6 -w - \
    > "$FIXTURE_TMP/http3_keyupdate_v$version.pcapng" \
    2> "$FIXTURE_TMP/dumpcap-v$version.log" &
  capture_pid=$!
  sleep 1
  SSLKEYLOGFILE="$FIXTURE_TMP/http3_keyupdate_v$version.keys" \
    "$FIXTURE_TMP/http3-traffic" client-updates 44433
  wait "$capture_pid"
  kill "$server_pid"
  wait "$server_pid" || true
 done
```

Check `security:key_updated` events and actual `transport:packet_sent` header
`key_phase_bit` values in **both** endpoint qlogs. Merely lowering the interval
is not evidence of an update. The committed captures' qlogs yielded these
first three sending generations (inclusive packet numbers):

| Version / sender | Generation 0, phase 0 | Generation 1, phase 1 | Generation 2, phase 0 | Last observed generation |
| --- | --- | --- | --- | --- |
| v1 client | 0–9 | 10–16 | 17–26 | 8 |
| v1 server | 0–9 | 10–19 | 20–29 | 8 |
| v2 client | 0–9 | 10–15 | 16–24 | 7 |
| v2 server | 0–7 | 8–17 | 18–27 | 7 |

The transport regression also decrypts these captures and asserts the final
8/7 generations in each direction. SDK regressions require all 24 complete
messages, their stream IDs, directions and exact bodies, plus file/stream raw
byte equivalence. Independent Python HMAC/HKDF expectations in
`transport/quic_decryptor_test.go` cover v1/v2 × AES-128/AES-256/ChaCha20;
these two captures cover AES-128 updates. The independent aioquic matrix below
adds real AES-256/ChaCha20 updates for both versions.

SHA-256 of the committed captures:

```text
bb79dfa129da4bbb0f0f783809715fa69fa57b35b0648522943ef200a6f33840  http3_keyupdate_v1.pcapng
9e5201ec0f6c4331076b48c5da9409ce0f5bdc2e388de41c25d1b4ae82d067b1  http3_keyupdate_v2.pcapng
```

## CID, Retry/VN, 0-RTT and cipher-suite matrix

`http3_lifecycle_aioquic.pcapng` / `.keys` are real Linux loopback traffic,
independently generated by **aioquic 1.3.0** (Python 3.14, cryptography 50.0.2,
pyOpenSSL 26.4.0) and captured by dumpcap. The SDK does not depend on aioquic.
The separate Python generator is necessary to select all three TLS 1.3 suites;
the existing Go generator cannot select them through `tls.Config.CipherSuites`.
Neither this capture nor its packet bytes are generated by SDK test helpers.

Each cell below contains three connections and four GET requests (eight SDK
messages). ServerHello cipher values were also checked directly with tshark.

| Wire version | Actual suite | Retry / migration | Accepted / rejected 0-RTT |
| --- | --- | --- | --- |
| `0x00000001` | `0x1301` AES-128-GCM | yes / yes | yes / yes |
| `0x00000001` | `0x1302` AES-256-GCM | yes / yes | yes / yes |
| `0x00000001` | `0x1303` ChaCha20-Poly1305 | yes / yes | yes / yes |
| `0x6b3343cf` | `0x1301` AES-128-GCM | yes / yes | yes / yes |
| `0x6b3343cf` | `0x1302` AES-256-GCM | yes / yes | yes / yes |
| `0x6b3343cf` | `0x1303` ChaCha20-Poly1305 | yes / yes | yes / yes |

For each suite/version, `/vN/SUITE/seed` uses Retry. Each v1 seed first offers v2,
receives VN, and then selects v1. `/migrate` uses the same connection after
`change_connection_id()` and a real UDP relay source-port change. `/accepted`
uses a saved session ticket and sends its request before the handshake completes.
For `/rejected`, the server ticket cache is cleared; the early request is rejected
and retransmitted at 1-RTT. Accepted/rejected connections reuse the relay tuple
but have different CIDs. Responses are exactly `reply PATH`.

The generator asserts the negotiated version, suite and acceptance flag, and
writes a local qlog and evidence JSON. The committed capture contains 237 UDP
packets, with no dumpcap drops. Endpoint qlogs record 12 sent 0-RTT packets,
12 RETIRE_CONNECTION_ID frames, 6 PATH_CHALLENGE and 6 PATH_RESPONSE frames.
There are 18 logical connections, 6 accepted resumptions, 6 rejected attempts,
and 24 request/response pairs. `TestQUICLifecycleCaptureAPIs` asserts all paths,
exact responses, stable migration identity, tuple reuse isolation, raw offsets,
early status, deduplication, and equivalence across external keys / embedded DSB /
streaming trailing DSB (including output before EOF).

Reproduce from the repository root on a Linux VM with Python venv, OpenSSL and
dumpcap available. No eCapture, eBPF, E01 or production endpoint is involved:

```sh
work=$(mktemp -d)
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install aioquic==1.3.0 cryptography==50.0.2 pyopenssl==26.4.0
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/server.key" \
  -out "$work/server.crt" -days 3 -subj /CN=localhost
sudo -n dumpcap -i lo -f 'udp port 44433' -w - \
  > "$work/http3_lifecycle_aioquic.pcapng" 2> "$work/capture.log" &
capture_pid=$!
trap 'kill "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true' EXIT
sleep 1
"$work/venv/bin/python" test/fixtures/http3_capture/aioquic_capture.py \
  --cert "$work/server.crt" --key "$work/server.key" --output "$work"
sleep 1
kill "$capture_pid"
wait "$capture_pid" || true
trap - EXIT

tshark -r "$work/http3_lifecycle_aioquic.pcapng" \
  -Y 'tls.handshake.type == 2' -T fields \
  -e quic.version -e tls.handshake.ciphersuite
# Inspect capture.log, lifecycle-evidence.json and lifecycle.qlog before replacing fixtures.
go test -run TestQUICLifecycleCaptureAPIs -v .
```

`TestQUICPacketProtectionMatrix` contains fixed independent aioquic/OpenSSL
vectors for all six cells, in addition to the RFC Initial/Retry and Key Update
vectors. To regenerate its packet vectors in the pinned venv, use
`CryptoContext.setup(cipher_suite=SUITE, secret=bytes(range(N)), version=VERSION)`
with N=48 for AES-256 and N=32 otherwise; call
`encrypt_packet(bytes.fromhex("410100"), bytes.fromhex("0b0003616263"), 256)`.
`derive_key_iv_hp` produces the corresponding key/IV/HP expectations. These are
algorithm vectors, not network capture fixtures.

Boundaries: this original lifecycle matrix does **not** exercise Key Update or
combine Retry with 0-RTT on one connection. Its mode uses unpatched aioquic with
pinned H3/configuration introspection hooks for static QPACK and negotiated
values. The two additional modes below use narrowly scoped fixture adapters.
Dynamic QPACK and draft-29 remain outside this matrix's scope. Its TLS test keys
and local self-signed certificate are only for reproducible test traffic.


## AES-256/ChaCha20 updates and Retry with 0-RTT

Two additional aioquic 1.3.0 modes use real loopback sockets and static QPACK.
The QUIC production code and its dependencies are unchanged. Capture files contain actual
network packets from dumpcap, not reconstructed or synthesized packets.

| Capture and matching `.keys` basename | Mode | Connections / HTTP messages | UDP packets / drops |
| --- | --- | --- | --- |
| `http3_keyupdate_matrix_aioquic` | `--key-update-matrix` | 4 / 24 | 128 / 0 |
| `http3_retry_early_aioquic` | `--retry-early` | 6 / 12 | 68 / 0 |

The update matrix uses ports 44469 (v1 AES-256), 44470 (v1 ChaCha20), 44471
(v2 AES-256), and 44472 (v2 ChaCha20). Each connection sends three GETs on
streams 0, 4, and 8, with paths `/ku/vN/SUITE/g0`, `/ku/vN/SUITE/g1`, and
`/ku/vN/SUITE/g2` (`SUITE` is `aes256` or `chacha`). Responses are exactly
`reply PATH`. The client initiates the first update and the server the second;
acknowledged exchanges separate updates. Both directions reach generations
0 → 1 → 2 and wire key phases 0 → 1 → 0. Sender assertions independently derive
successor secrets using Python standard-library HMAC/HKDF, check the unchanged
HP context, and recover every audited emitted header with the original HP key.

Pinned aioquic 1.3.0 hardcodes the v1 update label in `next_key_phase`. The update
mode locally adapts **only v2** to `quicv2 ku`, as required by
[RFC 9369 section 3.3.2](https://www.rfc-editor.org/rfc/rfc9369.html#section-3.3.2),
and restores the original function afterward. Native `apply_key_phase` already
preserves HP. This is interoperability with the disclosed fixture adapter, not
a claim that unmodified aioquic performs conforming v2 updates.

Retry uses AES-128 only, on ports 44473 (v1) and 44474 (v2). Each version has
three connections with one GET on stream 0: `/retry/vN/seed`,
`/retry/vN/accepted`, and `/retry/vN/rejected`. Responses again are `reply PATH`.
The seed has no Retry and establishes a ticket. Each other connection receives
exactly one Retry and actually sends its complete 29-byte request stream,
offset 0 with FIN, in 0-RTT both before and after Retry. The accepted connection
has no 1-RTT request replay. Clearing the server ticket cache rejects early data;
the rejected connection additionally retransmits that same request on stream 0
at 1-RTT. Peer status/body checks and qlog STREAM-frame assertions verify these
sequences; merely enabling a Retry flag is insufficient.

Native aioquic 1.3.0 `_connect` rebuilds TLS and packet spaces after Retry,
changing ClientHello/early secrets and losing sent early STREAM ranges. A
native comparison timed out with only the pre-Retry request in qlog. The Retry
mode keeps native Retry integrity validation but adapts its restart to preserve
TLS and packet spaces, derive new Initial keys from the new DCID, and requeue
sent Initial/early ranges through native loss callbacks. Native packet builders
still send all packets. Assertions require identical complete ClientHello bytes
and early secret, unchanged TLS state, new DCID/token, and strictly increasing
actual sent packet numbers, following
[RFC 9000 section 17.2.5.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.3).
No secret values are included in the evidence JSON. These adaptations are local
to this generator; neither the installed aioquic package nor SDK is patched.

Reuse the pinned venv and temporary self-signed certificate preparation above,
then run from the repository root. Both modes write keylogs, qlogs, and JSON
fixture evidence under their output directory; keep the certificate private key
and auxiliary logs outside Git.

```sh
for mode in key-update-matrix retry-early; do
  if [ "$mode" = key-update-matrix ]; then
    name=http3_keyupdate_matrix_aioquic
    filter='udp portrange 44469-44472'
    keyname=keyupdate-matrix.keys
  else
    name=http3_retry_early_aioquic
    filter='udp portrange 44473-44474'
    keyname=retry-early.keys
  fi
  mkdir "$work/$mode"
  sudo -n dumpcap -i lo -f "$filter" -w - \
    > "$work/$name.pcapng" 2> "$work/$mode/capture.log" &
  capture_pid=$!
  trap 'sudo -n kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true' EXIT
  sleep 1
  "$work/venv/bin/python" test/fixtures/http3_capture/aioquic_capture.py \
    --"$mode" --cert "$work/server.crt" --key "$work/server.key" \
    --output "$work/$mode"
  sleep 1
  sudo -n kill -INT "$capture_pid"
  wait "$capture_pid" || true
  trap - EXIT
  cp "$work/$mode/$keyname" "$work/$name.keys"
done

go test -race -run TestQUICStateMatrixCaptureAPIs .
go test -race -run TestQUICStateMatrixCapturedTransitions ./transport
```

`TestQUICStateMatrixCaptureAPIs` verifies exact
messages and raw bytes with external keys, seekable/non-seekable DSB, and both
trailing DSB direction orders, including output before EOF. The transport test
checks actual generation 2 in both directions, stable ClientHello random across
Retry, and accepted/rejected early state. Retry with other suites, combined
migration/Key Update, and draft-29 are not added by these captures.

```text
b4752bcbf7be06441ceccdb200793d29364a7285f35d572290bd6baa9aa10f5d  http3_keyupdate_matrix_aioquic.pcapng
fda2c22f946c1adf9e5773e895aefb67da93be809bd3b1bb51879bf60c61fa18  http3_keyupdate_matrix_aioquic.keys
34bd857c0f46c28841e04624a007147893a0ef4544d3187954e55d15ab61c1e2  http3_retry_early_aioquic.pcapng
ab4da2a29012ec3efb2653dcabd9cce3be0aec468e4e1259756e7796bda30366  http3_retry_early_aioquic.keys
```


## Dynamic QPACK and message-state fixture

`aioquic_capture.py --dynamic` uses independent aioquic 1.3.0 and pylsqpack
0.3.24; the production SDK imports neither package. Two captures have the same
application workload, each with two connections (`alpha`, `beta`) and zero
dumpcap drops:

| Capture and matching `.keys` basename | Wire version | Actual suite | UDP packets |
| --- | --- | --- | ---: |
| `http3_dynamic_aioquic` | v1 (`0x00000001`) | AES-256-GCM/SHA384 (`0x1302`) | 71 |
| `http3_dynamic_aioquic_v2` | v2 (`0x6b3343cf`) | AES-128-GCM/SHA256 (`0x1301`) | 72 |

Each connection sends `/LABEL/warmup`, `/LABEL/one`, `/LABEL/two`, `/LABEL/reset`.
Repeated `x-fixture-token: LABEL` × 16 values exercise dynamic references across
request streams in both directions. Encoder writes are delayed 80 ms and split
at one byte with a further 20 ms gap; the bytes are sent over actual QUIC sockets.

`/one` and `/two` receive 103 with `link: </asset>; rel=preload`, followed by 200,
body `reply /LABEL/PATH`, and `x-finished: LABEL` trailers. `/one` promises
`/LABEL/asset` (push ID 0, stream 15), body `asset LABEL`. `/reset` receives a
partial response then RESET_STREAM with error 0x10c; it has no complete response.
There are 20 message events: 8 requests, 6 final responses, 4 informational
responses, and 2 push responses. Raw output additionally observes 2 resets.

The pinned adapter keeps aioquic's header state at INITIAL after 1xx and sends
informational frames without advancing the final-response send state; QPACK
encoding/decoding remains entirely in pylsqpack. The generator asserts nonzero
Required Insert Counts and fragmented encoder writes in both directions, records
received fields/body/reset/push events in `dynamic-evidence.json`, and writes
`dynamic.qlog` for inspection. It also checks the actual version and suite;
tshark independently confirms the ServerHello values. The v2 capture has two
nonzero Required Insert Counts on the client and five on the server per connection,
with one client and two server encoder flushes split across writes. These
auxiliary evidence artifacts are local, not fixtures.

To reproduce, use the lifecycle section's venv/certificate/dumpcap setup, capture
to `http3_dynamic_aioquic.pcapng`, and run:

```sh
"$work/venv/bin/python" test/fixtures/http3_capture/aioquic_capture.py \
  --dynamic --cert "$work/server.crt" --key "$work/server.key" --output "$work"
# Stop and wait for the capture process before inspecting or copying the files.
# dynamic.keys is the matching SSLKEYLOG for http3_dynamic_aioquic.pcapng.

# For a separate v2 run, use the same UDP 44433 capture setup and write
# http3_dynamic_aioquic_v2.pcapng instead. Start capture before this command.
"$work/venv/bin/python" test/fixtures/http3_capture/aioquic_capture.py \
  --dynamic --version 2 --cert "$work/server.crt" --key "$work/server.key" \
  --output "$work/dynamic-v2"
# Stop and wait for capture, then pair it with dynamic-v2/dynamic.keys.
go test -run 'TestHTTP3Dynamic(Capture|EventCapture)APIs' -v .
```

`--version` applies to `--dynamic`; its default is v1/AES-256, preserving the
original fixture configuration. The v2 selection uses AES-128.
The regression compares field semantics, exact body bytes, stream IDs and
directions across seekable/non-seekable files, external keys, embedded/trailing
DSB, raw reconstruction and HTTPEvents. Duplicate DSB does not duplicate messages; blocked
headers resume before EOF. RFC 9204 Appendix B vectors, wrapping insert counts,
invalid SETTINGS, eviction, limits, reset and deadline tests complement this
capture. These two cells do not imply a dynamic HTTP/3 matrix for every cipher
suite or expand the real Key Update coverage described above.

### Accepted and rejected 0-RTT RESET

`http3_early_reset_aioquic.pcapng` and `.keys` contain 70 real loopback UDP
packets with zero dumpcap drops. `--early-reset` generates v1 on port 44467 and
v2 on port 44468, both using AES-128-GCM/SHA256. Each version has a seed,
accepted and rejected connection. Static QPACK keeps this test independent of
the dynamic-table workload above.

Each connection completes `GET /vN/MODE/ok`, with response body `reply PATH`.
The seed uses stream 0; accepted/rejected connections use stream 4 for this
normal exchange. Before their handshake completes, both send a partial
`POST /early/reset` on stream 0, declaring `content-length: 64` but transmitting
only ASCII `partial` followed by `00 ff` (nine body bytes), then RESET_STREAM with code `0x10c` and
final size 40. The independent sender records the exact 40-byte HTTP/3 prefix:

```text
011b0000d4d75086a0e41d139d09518960a3b28f4c5854153f5402363400097061727469616c00ff
```

The generator asserts actual qlog packets, not only configuration: accepted
connections send and receive the prefix and RESET at 0-RTT; rejected connections
send the RESET at 0-RTT and automatically retransmit it at 1-RTT. The rejecting
server receives only the 1-RTT RESET and no partial request bytes. All four
attempts have the same prefix/final size. Peer assertions check the incomplete
POST, reset stream/code and complete GET responses; qlog verifies the prefix
was sent before RESET with a nonzero final size. No network packets are synthesized.

Use the lifecycle section's venv and certificate, with a separate capture:

```sh
sudo -n dumpcap -i lo -f 'udp port 44467 or udp port 44468' -w - \
  > "$work/http3_early_reset_aioquic.pcapng" 2> "$work/early-reset-capture.log" &
capture_pid=$!
trap 'sudo -n kill -INT "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true' EXIT
sleep 1
"$work/venv/bin/python" test/fixtures/http3_capture/aioquic_capture.py \
  --early-reset --cert "$work/server.crt" --key "$work/server.key" \
  --output "$work/early-reset"
sudo -n kill -INT "$capture_pid"
wait "$capture_pid" || true
trap - EXIT
# Pair the capture with early-reset/early-reset.keys; inspect the capture log,
# early-reset-evidence.json and early-reset.qlog before replacing fixtures.
go test -run TestQUICEarlyResetCaptureAPIs -v .
```

The SDK checks complete messages, raw stage/status/reset metadata and HTTPEvents
across external keys and embedded/trailing DSB. A canceled partial POST must not
become a complete message; rejected early bytes remain separate in raw output.
This adds v1/v2 early RESET evidence, not Retry+0-RTT, dynamic QPACK within
0-RTT, other early-data cipher suites, or new Key Update combinations.

## Incremental HTTP and SSE fixture

The Go fixture's `stream-fixture` mode starts independent standard-library
TLS HTTP/1.1 and HTTP/2 peers and quic-go HTTP/3 peers on loopback. All three
flush three SSE records separately. In `long` mode they also transfer
17,825,829 bytes per response. Byte `i` is `i % 251`. The client checks every
byte and the negotiated HTTP version. The SDK replays the capture separately.

Run from this fixture module on the Linux VM. Use `mode=sse` for the small
committed fixture and `mode=long` for the larger on-demand regression.

```sh
work=$(mktemp -d)
mode=long
GOWORK=off go build -o "$work/traffic" .
sudo -n dumpcap -i lo -B 64 -f 'udp port 44433 or tcp port 44435 or tcp port 44436' \
  -w - > "$work/http_events_$mode.pcapng" 2> "$work/capture.log" &
cap_pid=$!
trap 'sudo -n kill -INT "$cap_pid" 2>/dev/null || true' EXIT
sleep 1
QUIC_GO_DISABLE_GSO=true SSLKEYLOGFILE="$work/http_events_$mode.keys" \
  "$work/traffic" stream-fixture "$mode"
sleep 1
sudo -n kill -INT "$cap_pid"
wait "$cap_pid"
trap - EXIT
cd ../../..
HTTP_EVENT_LONG_FIXTURE="$work/http_events_long" GOWORK=off go test -race \
  -run 'TestHTTPEventCaptureAPIs|TestHTTPEventsCaptureBeforeEOF' .
```

The committed SSE capture has 71 packets. The validation VM also captured
21,224 packets in long mode, with zero reported drops in both runs. The long
capture stays in the VM work directory. The test checks external keylog/file
and DSB/non-seekable stream paths, per-direction offsets, exact body bytes,
terminal events and raw QUIC STREAM payloads. The small fixture is also fed a
packet at a time with input held open to verify dispatch before the third SSE
record and before response completion. Unit regressions cover single large
HTTP chunks/frames, gzip limits, reset, truncation and blocked consumers.

## D08 DNS fixtures

`dns_capture.py` starts independent loopback DNS peers over TLS and QUIC using
Python TLS, dnspython 2.8.0, hyper-h2 4.3.0 and aioquic 1.3.0. It imports the
existing `StaticH3` fixture adapter from `aioquic_capture.py`; neither script
imports SDK code or writes capture packets. No eCapture or E01 is required.
All five captures share the external SSLKEYLOG file `d08_dns.keys`.

| Capture | Transport / port | Connections | Queries / responses | Scenario |
| --- | --- | ---: | ---: | --- |
| `d08_dot.pcapng` | TCP 44439 | 2 | 4 / 4 | Length-prefix fragmentation, pipelining, reversed replies, IDs 7/8 reused across connections |
| `d08_doh1.pcapng` | TCP 44442 | 1 | 2 / 2 | HTTP/1.1 GET base64url and POST, Content-Length and chunked replies |
| `d08_doh2.pcapng` | TCP 44443 | 1 | 2 / 2 | HTTP/2 GET/POST on streams 1/3, reversed replies and split DATA |
| `d08_doq.pcapng` | UDP 44444 | 2 | 4 / 4 | ALPN `doq`, concurrent streams with DNS ID zero, split length prefix and FIN |
| `d08_doh3.pcapng` | UDP 44445 | 1 | 2 / 2 | HTTP/3 GET/POST on concurrent streams, split DATA and FIN |

DoQ and DoH/3 select QUIC v1 with AES-128-GCM. DoH uses DNS ID zero on both
streams, so correlation must use the HTTP exchange. The peers verify complete
DNS response bytes and the A answer `192.0.2.1`. These fixtures do not claim
QUIC v2, 0-RTT, dynamic QPACK or failure/reset coverage; unit tests cover the
parser's invalid input, reset, limits and cancellation paths separately.

Run from the repository root on Linux with Python venv, OpenSSL, dumpcap and
tshark available. This creates a fresh keylog and captures actual packets:

```sh
work=$(mktemp -d)
umask 077
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install aioquic==1.3.0 dnspython==2.8.0 h2==4.3.0
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/peer.key" -out "$work/peer.crt" -subj /CN=localhost -days 1
sudo dumpcap -i lo -s 0 -B 64 \
  -f 'tcp port 44439 or tcp port 44442 or tcp port 44443 or udp port 44444 or udp port 44445' \
  -a duration:15 -w - > "$work/d08_dns.pcapng" 2> "$work/capture.log" &
capture_pid=$!
sleep 1
"$work/venv/bin/python" test/fixtures/http3_capture/dns_capture.py \
  --cert "$work/peer.crt" --key "$work/peer.key" \
  --keylog "$work/d08_dns.keys" --mode all
wait "$capture_pid"
for entry in dot:tcp:44439 doh1:tcp:44442 doh2:tcp:44443 doq:udp:44444 doh3:udp:44445; do
  mode=${entry%%:*}
  endpoint=${entry#*:}
  transport=${endpoint%%:*}
  port=${endpoint##*:}
  tshark -r "$work/d08_dns.pcapng" -Y "$transport.port == $port" -w "$work/d08_$mode.pcapng"
done
```

`--mode` also accepts one of `dot`, `doh1`, `doh2`, `doq` or `doh3`; every run
requires a new keylog path. Inspect `capture.log` for capture drops before
using the files. Keep the temporary certificate private key out of Git.
Splitting by port preserves captured network packets without synthesizing
traffic. To validate the committed captures and related unit tests:

```sh
CGO_ENABLED=1 go test -race -run 'TestD08ApplicationCaptureAPIs/(dot|doh1|doh2|doq|doh3)|TestDNS|TestDoT|TestDoQ|TestDoH' ./protocol .
```

The fixture regression checks message counts, DNS fields, query/reply association,
stream and connection identity with an external keylog and a trailing DSB on a
non-seekable stream. MQTT and Redis reproduction is in
[`../http_tcp_capture/README.md`](../http_tcp_capture/README.md#d08-mqtt-and-redis-fixtures).

### D11 QUIC DATAGRAM fixtures

`d11_datagram_v1.pcapng`, `d11_datagram_v2.pcapng` and `d11_datagram.keys`
come from `aioquic_capture.py --datagram` using aioquic 1.3.0 on Linux arm64.
They contain real loopback UDP traffic (ports 44465 and 44466), QUIC v1/v2,
TLS_AES_128_GCM_SHA256 and ALPN `fixture-datagram`. The capture has 92 packets
in total and zero drops. The generator does not import the SDK or write pcap.

Each version has three connections: a full handshake, accepted resumption with
0-RTT, and rejected resumption with an explicit application resend at 1-RTT.
Each exchanges five datagrams: empty, `00 ff 44 31 31`, `repeat`, `repeat`,
`tail`. The latter two connections first send `early 00 ff` at 0-RTT; the
rejected connection sends those same bytes again at 1-RTT. The echo endpoint
checks exact bytes and message counts. Its qlog also confirms multiple DATAGRAM
frames in one packet. Raw SDK output therefore contains 35 messages per capture
(18 client and 17 server), including authenticated rejected early data; equal
payloads in distinct messages remain separate. These captures use the explicit
length form (`0x31`); implicit length, malformed frames, replay/resource limits
and cancellation have separate deterministic unit tests. They do not establish
WebTransport, MASQUE, HTTP DATAGRAM or unreliable application delivery guarantees.

Use the lifecycle section's pinned venv and certificate setup, then run from the
repository root (replace `$work` with a new temporary directory):

```sh
sudo -v
sudo -n dumpcap -i lo -s 0 -B 64 -f 'udp portrange 44465-44466' -w - \
  > "$work/combined.pcapng" 2> "$work/capture.log" &
cap_pid=$!
sleep 1
"$work/venv/bin/python" test/fixtures/http3_capture/aioquic_capture.py \
  --cert "$work/server.crt" --key "$work/server.key" --output "$work" --datagram
sleep 1 # Drain actual final packets before stopping capture.
sudo -n kill -INT "$cap_pid"
wait "$cap_pid"
tshark -r "$work/combined.pcapng" -Y 'udp.port == 44465' -w "$work/d11_datagram_v1.pcapng"
tshark -r "$work/combined.pcapng" -Y 'udp.port == 44466' -w "$work/d11_datagram_v2.pcapng"
```

The keylog and both captures are the only required SDK inputs. Private certificate
keys and the independent qlog/evidence files stay in the temporary directory.
`TestD11QUICDatagramCaptureAPIs` checks file decoding and non-seekable input with
both late DSB orders, output before EOF, repeated DSB and duplicated real packet
blocks. It also verifies the existing requirement for explicit raw output when
ALPN is outside the supported application parsers.
