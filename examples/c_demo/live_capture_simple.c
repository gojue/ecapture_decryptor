/*
 * live_capture_simple.c
 *
 * Example: Simple demonstration of live traffic decryption API
 * Note: This shows the API usage. Full implementation requires pcap library.
 *
 * Usage: ./live_capture_simple <device> <keylog_file> <output_json> <seconds>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libecapture_decryptor.h>

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <device> <keylog_file> <output_json> <seconds>\n", argv[0]);
        fprintf(stderr, "Example: %s en0 sslkey.log output.json 30\n", argv[0]);
        fprintf(stderr, "\nNote: This demo shows the API. Live capture from device requires\n");
        fprintf(stderr, "      pcap library integration in the Go implementation.\n");
        return 1;
    }

    const char *device = argv[1];
    const char *keylog_file = argv[2];
    const char *output_file = argv[3];
    int duration = atoi(argv[4]);

    if (duration <= 0) {
        fprintf(stderr, "ERROR: Duration must be positive\n");
        return 1;
    }

    // Get library version
    char *version = GetVersion();
    printf("Using library: %s\n", version);
    FreeString(version);

    printf("Starting live traffic decryption...\n");
    printf("  Device: %s\n", device);
    printf("  SSL keylog: %s\n", keylog_file);
    printf("  Output JSON: %s\n", output_file);
    printf("  Duration: %d seconds\n", duration);

    // Prepare error buffer
    char error_buf[512] = {0};

    // Start live traffic decryption (non-blocking)
    int handle = DecryptLiveTrafficToFile(
        (char*)device,
        (char*)keylog_file,
        (char*)output_file,
        error_buf,
        sizeof(error_buf)
    );

    if (handle == 0) {
        fprintf(stderr, "ERROR: Failed to start live capture\n");
        if (strlen(error_buf) > 0) {
            fprintf(stderr, "Details: %s\n", error_buf);
        }
        return 1;
    }

    printf("✓ Live capture started (handle: %d)\n", handle);
    printf("  Capturing for %d seconds...\n", duration);

    // Let it run for specified duration
    for (int i = 0; i < duration; i++) {
        sleep(1);

        // Check for errors
        char check_buf[512] = {0};
        if (GetLiveTrafficError(handle, check_buf, sizeof(check_buf)) != 0) {
            fprintf(stderr, "WARNING: Error during capture: %s\n", check_buf);
        }

        if ((i + 1) % 5 == 0) {
            printf("  ... %d seconds elapsed\n", i + 1);
        }
    }

    printf("  Stopping capture...\n");

    // Stop the live capture
    int ret = StopLiveTraffic(handle);
    if (ret != 0) {
        fprintf(stderr, "WARNING: Stop returned code %d\n", ret);
    }

    printf("✓ Live capture stopped\n");
    printf("✓ Results written to: %s\n", output_file);

    return 0;
}

