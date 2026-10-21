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
