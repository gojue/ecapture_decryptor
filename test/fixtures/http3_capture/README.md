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
