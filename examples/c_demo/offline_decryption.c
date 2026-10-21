/*
 * offline_decryption.c
 *
 * Example: Decrypt offline pcap file using libecapture_decryptor static library
 *
 * Usage: ./offline_decryption <pcapng_file> [keylog_file] <output_json>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libecapture_decryptor.h>

int main(int argc, char *argv[]) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <pcapng_file> [keylog_file] <output_json>\n", argv[0]);
        fprintf(stderr, "Omit keylog_file when the pcapng contains a TLS DSB.\n");
        return 1;
    }

    const char *pcap_file = argv[1];
    const char *keylog_file = argc == 4 ? argv[2] : "";
    const char *output_file = argv[argc - 1];

    // Get library version
    char *version = GetVersion();
    printf("Using library: %s\n", version);
    FreeString(version);

    printf("Decrypting pcap file...\n");
    printf("  Input pcap: %s\n", pcap_file);
    printf("  SSL keylog: %s\n", *keylog_file ? keylog_file : "pcapng DSB");
    printf("  Output JSON: %s\n", output_file);

    // Prepare error buffer
    char error_buf[512] = {0};

    // Decrypt pcap file to JSON
    int ret = DecryptPcapToFile(
        (char*)pcap_file,
        (char*)keylog_file,
        (char*)output_file,
        "json",
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

    printf("✓ Decryption completed successfully!\n");
    printf("✓ Results written to: %s\n", output_file);

    return 0;
}

