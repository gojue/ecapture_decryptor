<p align="center">
  <strong>eCapture Decryptor</strong><br />
  A Go library that decrypts TLS/QUIC traffic from pcapng captures using SSLKEYLOG keys or pcapng-embedded TLS Decryption Secrets Blocks (DSB).
</p>

<p align="center">
  <strong>English</strong> · <a href="./README-zh_Hans.md">汉字</a><br />
  <a href="https://github.com/gojue/ecapture_decryptor/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/gojue/ecapture_decryptor?display_name=tag&include_prereleases&sort=semver" /></a>
  <a href="https://pkg.go.dev/github.com/gojue/ecapture_decryptor"><img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/gojue/ecapture_decryptor.svg" /></a>
</p>

> [!NOTE]
> The repository is named `ecapture_decryptor` and the Go module path is `github.com/gojue/ecapture_decryptor`; the root package, C library files, and release archives all use the `ecapture_decryptor` name.

----

<!-- MarkdownTOC autolink="true" -->
- [Introduction](#introduction)
- [Features](#features)
- [Getting started](#getting-started)
  - [Installation](#installation)
  - [Decrypt a pcapng file](#decrypt-a-pcapng-file)
  - [Incremental pcapng + DSB](#incremental-pcapng--dsb)
  - [Basic usage](#basic-usage)
- [Usage](#usage)
- [Building](#building)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [License](#license)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
<!-- /MarkdownTOC -->

# Introduction

eCapture Decryptor decrypts TLS and QUIC traffic captured in pcapng files. TLS secrets can come from a standalone SSLKEYLOG file, from a TLS Decryption Secrets Block (DSB) embedded in the pcapng, or from both sources at once.

The SDK only decrypts and parses protocols — it does not impose an output format. Results are delivered as `DecryptedPacket` values that callers can process however they like (JSON, HAR, streaming, etc.).

# Features

- 🔓 **Decrypt TLS/QUIC traffic**: supports external SSLKEYLOG files and pcapng-embedded DSB
- 🌐 **Multi-protocol support**: HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3, WebSocket
- 📦 **Flexible output**: emits `DecryptedPacket` values for callers to handle freely
- **Raw streams and diagnostics**: opt into authenticated TLS bytes or QUIC STREAM chunks with `DecryptPcapngStreamWithOptions` / `WithOptions`; see the [API contract](docs/API.md#decryptpcapngstreamwithoptions--withoptions).
- 🔧 **Multiple usage modes**: Go library, static library (`.a`), command-line tool
- 🎯 **Clear responsibility**: decryption and protocol parsing only, no forced output format

### QUIC / HTTP/3 input requirements

Decrypting HTTP/3 requires a bidirectional UDP capture that includes the client Initial (containing the ClientHello), plus the matching TLS 1.3 SSLKEYLOG. Keys may be provided as an external file or inside the pcapng DSB. The parser reassembles data by QUIC connection, packet number, and STREAM offset, then emits `http/3` `DecryptedPacket` values per HTTP/3 request stream.

The [Linux HTTP/3 captures](test/fixtures/http3_capture/README.md) and the [Linux HTTP/1.x and HTTP/2 captures](test/fixtures/http_tcp_capture/README.md) in the repository were captured with `tcpdump` and eCapture, and cover external keys, embedded DSB, and DSB-file streaming. End-to-end tests currently cover QUIC v1; key derivation for v2 and draft-29 is implemented but lacks real-capture tests. HTTP/3 header parsing supports the QPACK static table and literals; connections that use the dynamic table, QUIC key updates, and connection migration are not yet covered.

# Getting started

## Installation

```bash
go get github.com/gojue/ecapture_decryptor
```

## Decrypt a pcapng file

`DecryptPcapFile`'s `keylogReader` may be `nil`, in which case keys are read from the pcapng DSB. When an SSLKEYLOG reader is provided, the pcapng DSB is also read — both sources can be used together.

```go
// Use only the DSB embedded in the pcapng.
err := ecapture_decryptor.DecryptPcapFile(nil, pcapngFile, packetChan)

// Use an external SSLKEYLOG file; a pcapng DSB is also loaded if present.
err = ecapture_decryptor.DecryptPcapFile(keylogFile, pcapngFile, packetChan)
```

## Incremental pcapng + DSB

`DecryptPcapngStream(ctx, input, emit)` reads complete blocks from a growing pcapng `io.ReadCloser` and loads NSS Key Log keys as soon as a DSB arrives. The DSB may appear after the handshake, the application data, or even after the last network packet. The SDK reassembles and deduplicates by TCP sequence number and emits complete HTTP/1.1 or HTTP/2 request/response pairs; an error returned by `emit` stops reading and is propagated. Cancelling `ctx` closes `input` to unblock reads. Callers should provide an `input` implementation that can be interrupted by `Close`, such as an `io.PipeReader` or a network connection.

```go
err := ecapture_decryptor.DecryptPcapngStream(ctx, input, func(message *types.DecryptedPacket) error {
    // message.Data is the complete HTTP message; Metadata contains host/authority and stream_id.
    return handle(message)
})
```

eCapture integration, and its source and binary distribution (including commercial use), is covered by the **eCapture Integration Exception** in [LICENSE](LICENSE). Other SDK uses remain subject to the original license terms.

## Basic usage

```go
package main

import (
    "log"
    "os"

    "github.com/gojue/ecapture_decryptor"
    "github.com/gojue/ecapture_decryptor/types"
)

func main() {
    keylog, _ := os.Open("sslkey.log")
    pcap, _ := os.Open("traffic.pcap")
    defer keylog.Close()
    defer pcap.Close()

    // Channel that receives decrypted packets.
    packetChan := make(chan *types.DecryptedPacket, 100)

    // Process decrypted packets.
    go func() {
        for packet := range packetChan {
            log.Printf("[%s] %s: %d bytes",
                packet.Protocol,   // "http/1.1", "http/2", ...
                packet.Direction,  // "request" or "response"
                len(packet.Data))  // decrypted data
        }
    }()

    // Decrypt.
    err := ecapture_decryptor.DecryptPcapFile(keylog, pcap, packetChan)
    if err != nil {
        log.Fatal(err)
    }

    close(packetChan)
}
```

# Usage

The public API lives in the root package:

- `DecryptPcapFile(keylogReader, pcapFileHandle, packetChan)` — decrypt a pcap/pcapng file
- `DecryptLiveTraffic(keylogReader, pcapHandle, packetChan)` — decrypt a live/streamed pcap source
- `DecryptPcapngStream(ctx, input, emit)` — stream-decrypt a growing pcapng with late DSB
- `DecryptWithConfig(config)` / `NewDecryptorConfig()` — builder-based advanced configuration

The [command-line example](examples/go_demo/README.md) (`bin/ecapture_decryptor`) demonstrates offline decryption and JSON/HAR export:

```bash
./bin/ecapture_decryptor -pcap traffic.pcapng -sslkeylog sslkey.log -v
./bin/ecapture_decryptor -pcap traffic-with-dsb.pcapng -json output.json
./bin/ecapture_decryptor -pcap traffic.pcapng -sslkeylog sslkey.log -har output.har
```

For the full API reference, the `DecryptedPacket` model, protocol metadata, and C/C++ usage, see:

- **[API reference](docs/API.md)** — complete Go API, data types, and metadata formats
- **[C/C++ examples](examples/c_demo/README.md)** — static library usage, C API functions, and compiler flags

# Building

```bash
make build-static                  # static library (.a)
make build-shared                  # shared library (.dylib / .so)
make -C examples/go_demo build     # Go command-line example
make -C examples/c_demo all        # C example programs
make test                          # run tests
make clean                         # clean build artifacts
```

Build artifacts include `bin/ecapture_decryptor` (CLI), `lib/libecapture_decryptor.a` (static), `lib/libecapture_decryptor.dylib`/`.so` (shared), `include/libecapture_decryptor.h` (C header), and the C demo binaries. Default builds apply `-s -w` and `-trimpath` to reduce binary size.

See **[Makefile guide](docs/MAKEFILE_GUIDE.md)** and the **[development guide](docs/DEVELOPMENT.md)** for details.

# Architecture

The SDK is organized as layers: public API (`api.go` / `factory.go`) → protocol parsing (`protocol/`) → transport decryption (`transport/`, TLS/QUIC) → cryptography (`crypto/`, key management) → packet capture (`gopacket`). The core emits `DecryptedPacket` values; HAR and JSON output are produced by callers or example programs.

See **[Architecture](docs/ARCHITECTURE.md)** for the layered design, module responsibilities, data flow, and design principles.

# Documentation

- **[Documentation index](docs/README.md)** — navigation for users, developers, and maintainers
- **[CHANGELOG.md](CHANGELOG.md)** — version history
- **[API reference](docs/API.md)** · **[Architecture](docs/ARCHITECTURE.md)** · **[Development guide](docs/DEVELOPMENT.md)** · **[Makefile guide](docs/MAKEFILE_GUIDE.md)**
- **[Release guide](docs/RELEASE_GUIDE.md)** · **[Release quick reference](docs/RELEASE_QUICKREF.md)** · **[Release examples](docs/RELEASE_EXAMPLES.md)**

# License

### ⚠️ Dual license

This project uses a **dual-license** model:

#### 1. Source code license

**Copyright © 2024-2026 CFC4N (cfc4n.cs@gmail.com). All rights reserved.**

The source code is **proprietary**. Any use, copying, modification, or distribution is prohibited without explicit written permission. Viewing the source grants no usage rights.

#### 2. Binary library license

**Copyright © 2024-2026 CFC4N (cfc4n.cs@gmail.com). All rights reserved.**

Compiled binary libraries (`.a`, `.so`, `.dylib`) may be used for **non-commercial purposes** only: personal use, research and education, evaluation and testing, and linking with non-commercial applications. Commercial use requires a separate license; reverse engineering, modification, redistribution of modified versions, and removal of copyright notices are prohibited.

#### Attribution

```
This software uses the eCapture Decryptor library
Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com)
Licensed for Non-Commercial Use
https://github.com/gojue/ecapture_decryptor
```

#### Commercial license

Contact **cfc4n.cs@gmail.com** with subject `Commercial License Inquiry - eCapture Decryptor`.

- **[LICENSE](LICENSE)** — full license (Chinese & English)
- **[LICENSE-BINARY](LICENSE-BINARY)** — binary library license (Chinese & English)
- **[COPYRIGHT](COPYRIGHT)** — copyright notice
- **[License summary](docs/LICENSE-SUMMARY.md)** — quick reference

# Contributing

Because the source code is proprietary, external contributions are not currently accepted. Issues and suggestions are welcome.

# Acknowledgements

This project builds on the following excellent open-source projects:

- [gopacket](https://github.com/google/gopacket) — packet processing
- The Go standard library `crypto/tls` package

---

> [!IMPORTANT]
> 1. You must have a legitimate SSLKEYLOG file to use this tool.
> 2. Ensure you are authorized to decrypt the target traffic.
> 3. Comply with all applicable laws and regulations.
> 4. Commercial use requires a separate license.

**Copyright © 2024-2026 CFC4N. All Rights Reserved.**
