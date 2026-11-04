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
only AES-128 has real-traffic update coverage here. CID migration, Retry,
0-RTT and the full D04.5 traffic matrix remain separate tasks.

SHA-256 of the committed captures:

```text
bb79dfa129da4bbb0f0f783809715fa69fa57b35b0648522943ef200a6f33840  http3_keyupdate_v1.pcapng
9e5201ec0f6c4331076b48c5da9409ce0f5bdc2e388de41c25d1b4ae82d067b1  http3_keyupdate_v2.pcapng
```
