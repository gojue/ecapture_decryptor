# C Demo Examples

This directory contains C language examples demonstrating how to use the `libecapture_decryptor` static library.

## Prerequisites

1. Build the static library first:
```bash
cd ../..
make build-lib
```

This generates (following standard library layout):
- `lib/libecapture_decryptor.a` - Static library
- `include/libecapture_decryptor.h` - C header file

## Directory Structure

```
project_root/
├── lib/                          # Static libraries (.a)
│   └── libecapture_decryptor.a
├── include/                      # Header files (.h)
│   └── libecapture_decryptor.h
└── examples/c_demo/              # C examples
    ├── Makefile
    ├── offline_decryption.c
    ├── stream_decryption.c
    └── live_capture_simple.c
```

## Building the Examples

```bash
make all
```

This builds three demo programs:
- `offline_decryption` - Decrypt offline pcap files
- `stream_decryption` - Decrypt pcap streams (from stdin/pipe)
- `live_capture_simple` - Live traffic capture demo

## Examples

### 1. Offline Decryption

Decrypt a pcap file to JSON format:

```bash
./offline_decryption traffic.pcap sslkey.log output.json
```

Example with test data:
```bash
./offline_decryption \
    ../../test/testdata/all_clients.pcap \
    ../../test/testdata/all_clients_sslkey.log \
    output.json
```

### 2. Stream Decryption

Decrypt pcap data from stdin (useful for pipes):

```bash
# From a file
cat traffic.pcap | ./stream_decryption sslkey.log output.json

# From tcpdump (live capture via pipe)
tcpdump -i eth0 -w - | ./stream_decryption sslkey.log output.json

# With tcpdump filter
tcpdump -i eth0 -w - 'port 443' | ./stream_decryption sslkey.log output.json
```

### 3. Live Capture (API Demo)

Demonstrates the live capture API (requires pcap library integration):

```bash
./live_capture_simple en0 sslkey.log output.json 30
```

**Note**: The live capture feature requires pcap library integration in the Go implementation. This demo shows the API usage pattern.

## Running Tests

```bash
# Test offline decryption
make test

# Test stream decryption
make test-stream
```

## API Functions

The library exports the following C functions:

### GetVersion()
```c
char* GetVersion();
```
Returns the library version string. Remember to call `FreeString()` on the result.

### DecryptPcapToFile()
```c
int DecryptPcapToFile(
    char* pcapPath,
    char* keylogPath,
    char* outputPath,
    char* format,        // "json"
    char* errorBuf,
    int errorBufLen
);
```
Decrypts a pcap file and writes JSON output.

**Returns:**
- `0` - Success
- `1` - Failed to open keylog file
- `2` - Failed to open pcap file
- `3` - Decryption failed
- `4` - Failed to create output file
- `5` - Failed to write output
- `6` - Unsupported format

### DecryptPcapStreamToFile()
```c
int DecryptPcapStreamToFile(
    char* keylogPath,
    char* outputPath,
    int maxPackets,      // 0 = unlimited
    char* errorBuf,
    int errorBufLen
);
```
Decrypts pcap data from stdin and writes JSON output.

**Returns:** Same as `DecryptPcapToFile()`

### DecryptLiveTrafficToFile()
```c
int DecryptLiveTrafficToFile(
    char* deviceName,
    char* keylogPath,
    char* outputPath,
    char* errorBuf,
    int errorBufLen
);
```
Starts live traffic decryption (non-blocking).

**Returns:** Handle ID (>0) on success, 0 on error

### StopLiveTraffic()
```c
int StopLiveTraffic(int handleID);
```
Stops a live capture session.

**Returns:**
- `0` - Success
- `1` - Invalid handle
- `2` - Timeout

### GetLiveTrafficError()
```c
int GetLiveTrafficError(
    int handleID,
    char* errorBuf,
    int errorBufLen
);
```
Gets the last error from a live capture session.

**Returns:**
- `0` - No error
- `1` - Error exists (written to errorBuf)

### FreeString()
```c
void FreeString(char* str);
```
Frees strings allocated by Go (e.g., from `GetVersion()`).

## Compiler Flags

### Linux
```bash
gcc -o myapp myapp.c \
    -I../../bin \
    -L../../bin \
    -lecapture_decryptor \
    -lpthread -lresolv
```

### macOS
```bash
gcc -o myapp myapp.c \
    -I../../bin \
    -L../../bin \
    -lecapture_decryptor \
    -lpthread -lresolv \
    -framework CoreFoundation
```

### C++
```bash
g++ -o myapp myapp.cpp \
    -I../../bin \
    -L../../bin \
    -lecapture_decryptor \
    -lpthread -lresolv
```

## Output Format

The JSON output contains an array of decrypted packets:

```json
[
  {
    "Protocol": "http/1.1",
    "Direction": "request",
    "Data": "R0VUIC9pbmRleC5odG1sIEhUVFAvMS4xDQo...",
    "Timestamp": "2024-01-15T10:30:00Z",
    "ConnectionID": "192.168.1.100:54321->93.184.216.34:443",
    "Metadata": {
      "method": "GET",
      "url": "https://example.com/index.html",
      "headers": {...}
    }
  }
]
```

## Troubleshooting

**Library not found error:**
```
ld: library not found for -lecapture_decryptor
```
Solution: Run `make build-lib` in the root directory first.

**Undefined symbols error:**
```
Undefined symbols for architecture arm64
```
Solution: Add required system libraries (`-lpthread -lresolv` and `-framework CoreFoundation` on macOS).

**Runtime errors:**
Ensure your keylog file format is correct and matches the pcap file's connections.

## Integration Example

Here's a minimal C program:

```c
#include <stdio.h>
#include "libecapture_decryptor.h"

int main() {
    char error[256];
    int ret = DecryptPcapToFile(
        "traffic.pcap",
        "sslkey.log",
        "output.json",
        "json",
        error,
        sizeof(error)
    );
    
    if (ret != 0) {
        fprintf(stderr, "Error: %s\n", error);
        return 1;
    }
    
    printf("Success!\n");
    return 0;
}
```

Compile:
```bash
gcc -o decrypt decrypt.c -I../../bin -L../../bin -lecapture_decryptor -lpthread -lresolv
```

## License

Same as the main project (MIT License).

