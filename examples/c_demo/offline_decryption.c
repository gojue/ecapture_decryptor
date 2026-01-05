/*
 * offline_decryption.c
 *
 * Example: Decrypt offline pcap file using libecapture_decryptor static library
 *
 * Usage: ./offline_decryption <pcap_file> <keylog_file> <output_json>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libecapture_decryptor.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <pcap_file> <keylog_file> <output_json>\n", argv[0]);
        fprintf(stderr, "Example: %s traffic.pcap sslkey.log output.json\n", argv[0]);
        return 1;
    }

    const char *pcap_file = argv[1];
    const char *keylog_file = argv[2];
    const char *output_file = argv[3];

    // Get library version
    char *version = GetVersion();
    printf("Using library: %s\n", version);
    FreeString(version);

    printf("Decrypting pcap file...\n");
    printf("  Input pcap: %s\n", pcap_file);
    printf("  SSL keylog: %s\n", keylog_file);
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

