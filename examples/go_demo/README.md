# Go Demo Example

This directory contains a Go language example demonstrating how to use the ecapture_decryptor library.

## Overview

This demo program showcases the decryption of TLS/SSL traffic from pcap files using the ecapture_decryptor Go API.

## Features

- Decrypt HTTPS traffic from pcap files
- Support for multiple output formats:
  - HAR (HTTP Archive format)
  - JSON (custom format)
- TLS/SSL key log file support
- pcapng DSB support without a separate key log file
- Support for HTTP/1.1, HTTP/2, HTTP/3, and WebSocket protocols

## Building

From the project root directory:

```bash
make -C examples/go_demo build
```

This will build the binary: `bin/ecapture_decryptor`

## Usage

### Basic Usage

```bash
./bin/ecapture_decryptor -pcap <pcap_file> -sslkeylog <keylog_file> -har <output.har>
```

### Output to JSON

```bash
./bin/ecapture_decryptor -pcap <pcap_file> -sslkeylog <keylog_file> -json <output.json>
```

### pcapng with embedded DSB

```bash
./bin/ecapture_decryptor -pcap <pcapng_with_dsb> -json <output.json>
```

### Example with Test Data

```bash
./bin/ecapture_decryptor \
    -pcap test/testdata/all_clients.pcap \
    -sslkeylog test/testdata/all_clients_sslkey.log \
    -har test/result/all_clients.har
```

## Command-Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `-pcap` | Input pcap file path | Yes |
| `-sslkeylog` | External SSL/TLS keylog file path; omit for pcapng with DSB | No |
| `-har` | Output HAR file path | Optional* |
| `-json` | Output JSON file path | Optional* |

If neither output option is specified, the program prints decryption statistics.

## Files

- `main.go` - Main program entry point
- `har_converter.go` - HAR format converter
- `har_types.go` - HAR format type definitions
- `json_converter.go` - JSON format converter

## Architecture

```
main.go
  ↓
decryptor.DecryptPcapFile(keylogReader, pcapFile, packets)
  ↓
Parse pcap + Decrypt TLS/SSL
  ↓
Protocol Parsers (HTTP/1.1, HTTP/2, HTTP/3, WebSocket)
  ↓
Output Converters
  ├─→ HAR Converter (har_converter.go)
  └─→ JSON Converter (json_converter.go)
```

## API Usage Example

See [main.go](main.go) for the complete call to
`decryptor.DecryptPcapFile(keylogReader, pcapFile, packetChan)` and the
JSON/HAR output handling.

## Testing

Run the test with example data:

```bash
make -C examples test
```

Or manually:

```bash
./bin/ecapture_decryptor \
    -pcap test/testdata/all_clients.pcap \
    -sslkeylog test/testdata/all_clients_sslkey.log \
    -har test/result/all_clients.har
```

## Related Directories

- `../c_demo/` - C language examples using the static library
- `../../capi/` - C API wrapper (for C/C++ integration)
- `../../protocol/` - Protocol parsers implementation
- `../../crypto/` - TLS/SSL decryption implementation

## Notes

- Requires Go 1.21 or later
- The decryptor supports multiple TLS/SSL versions
- SSL keylog file format follows the NSS Key Log format used by browsers
- Output files can be imported into tools like Wireshark or HAR viewers

