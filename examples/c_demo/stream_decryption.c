/*
 * stream_decryption.c
 *
 * Example: Decrypt pcap stream from stdin (e.g., piped from tcpdump)
 *
 * Usage: tcpdump -i eth0 -w - | ./stream_decryption <keylog_file> <output_json>
 *    or: cat traffic.pcap | ./stream_decryption <keylog_file> <output_json>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libecapture_decryptor.h>

int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: <pcapng_stream> | %s [keylog_file] <output_json>\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  tcpdump -i eth0 -w - | %s sslkey.log output.json\n", argv[0]);
        fprintf(stderr, "  cat traffic-with-dsb.pcapng | %s output.json\n", argv[0]);
        return 1;
    }

    const char *keylog_file = argc == 3 ? argv[1] : "";
    const char *output_file = argv[argc - 1];

    // Get library version
    char *version = GetVersion();
    printf("Using library: %s\n", version);
    FreeString(version);

    printf("Decrypting pcap stream from stdin...\n");
    printf("  SSL keylog: %s\n", *keylog_file ? keylog_file : "pcapng DSB");
    printf("  Output JSON: %s\n", output_file);
    printf("  (Reading from stdin, press Ctrl+C to stop)\n");

    // Prepare error buffer
    char error_buf[512] = {0};

    // Decrypt pcap stream (reads from stdin)
    // maxPackets = 0 means unlimited
    int ret = DecryptPcapStreamToFile(
        (char*)keylog_file,
        (char*)output_file,
        0,  // maxPackets (0 = unlimited)
        error_buf,
        sizeof(error_buf)
    );

    if (ret != 0) {
        fprintf(stderr, "ERROR: Decryption failed (code %d)\n", ret);
        if (strlen(error_buf) > 0) {
            fprintf(stderr, "Details: %s\n", error_buf);
        }
        return ret;
    }

    printf("✓ Stream decryption completed!\n");
    printf("✓ Results written to: %s\n", output_file);

    return 0;
}

