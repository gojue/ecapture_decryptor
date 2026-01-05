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
- Support for HTTP/1.1, HTTP/2, HTTP/3, and WebSocket protocols

## Building

From the project root directory:

```bash
make build
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
| `-sslkeylog` | SSL/TLS keylog file path | Yes |
| `-har` | Output HAR file path | Optional* |
| `-json` | Output JSON file path | Optional* |

*At least one output format (-har or -json) must be specified.

## Files

- `main.go` - Main program entry point
- `har_converter.go` - HAR format converter
- `har_types.go` - HAR format type definitions
- `json_converter.go` - JSON format converter

## Architecture

```
main.go
  ↓
api.NewDecryptor()
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

```go
import "github.com/cfc4n/ecapture_decryptor"

// Create decryptor
decryptor, err := api.NewDecryptor(pcapFile, sslKeylogFile)
if err != nil {
    log.Fatal(err)
}
defer decryptor.Close()

// Decrypt and get packets
packets, err := decryptor.DecryptAll()
if err != nil {
    log.Fatal(err)
}

// Convert to HAR format
har := ConvertToHAR(packets)

// Save to file
saveHAR(har, outputFile)
```

## Testing

Run the test with example data:

```bash
make test
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

