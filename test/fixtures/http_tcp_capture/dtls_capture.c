//go:build ignore

// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

// Independent OpenSSL DTLS peers. Only real loopback UDP traffic is generated;
// a separate packet capture program records it. No SDK code is linked.
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "fixture failed: %s at %d\n", #x, __LINE__); ERR_print_errors_fp(stderr); exit(1); } } while (0)

static FILE *keylog;
static const unsigned char request[] = "dtls request\x00\xff\r\n";
static const unsigned char response[] = "dtls response\x00\xfe\r\n";
// A fixed fixture-only cookie makes this local transcript reproducible. This
// is not a production server's address-bound denial-of-service protection.
static const unsigned char cookie[] = "d11-local-cookie";

struct peer {
    SSL_CTX *ctx;
    const char *mode, *cipher;
    int fd, server, hvr;
    struct sockaddr_in remote;
};

static void log_secret(const SSL *ssl, const char *line) {
    (void)ssl;
    CHECK(fprintf(keylog, "%s\n", line) > 0);
    CHECK(fflush(keylog) == 0);
}

static int make_cookie(SSL *ssl, unsigned char *out, unsigned int *len) {
    (void)ssl;
    memcpy(out, cookie, sizeof(cookie)-1);
    *len = sizeof(cookie)-1;
    return 1;
}

static int verify_cookie(SSL *ssl, const unsigned char *in, unsigned int len) {
    (void)ssl;
    return len == sizeof(cookie)-1 && memcmp(in, cookie, len) == 0;
}

static void message(int write_p, int version, int type, const void *buf,
                    size_t len, SSL *ssl, void *arg) {
    (void)version; (void)arg;
    struct peer *p = SSL_get_app_data(ssl);
    if (write_p && type == SSL3_RT_HANDSHAKE && len >= 12 && ((const unsigned char *)buf)[0] == 3) p->hvr++;
}

static SSL_CTX *context(const char *cert, const char *key, const char *cipher, int server) {
    SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
    CHECK(ctx != NULL);
    CHECK(SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION));
    CHECK(SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION));
    CHECK(SSL_CTX_set_cipher_list(ctx, cipher));
    CHECK(SSL_CTX_set1_groups_list(ctx, "P-256"));
    SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);
    SSL_CTX_set_msg_callback(ctx, message);
    if (server) {
        CHECK(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM));
        CHECK(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM));
        CHECK(SSL_CTX_check_private_key(ctx));
        SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);
        SSL_CTX_set_cookie_generate_cb(ctx, make_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_keylog_callback(ctx, log_secret);
    }
    return ctx;
}

static int udp_socket(struct sockaddr_in *address, unsigned short port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address->sin_port = htons(port);
    CHECK(bind(fd, (struct sockaddr *)address, sizeof(*address)) == 0);
    socklen_t len = sizeof(*address);
    CHECK(getsockname(fd, (struct sockaddr *)address, &len) == 0);
    struct timeval timeout = {5, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}

static void receive(SSL *ssl, const unsigned char *want, size_t len) {
    unsigned char buf[128];
    int n = SSL_read(ssl, buf, sizeof(buf));
    CHECK(n == (int)len && memcmp(buf, want, len) == 0);
}

static void *run_peer(void *arg) {
    struct peer *p = arg;
    SSL *ssl = SSL_new(p->ctx);
    CHECK(ssl != NULL);
    SSL_set_app_data(ssl, p);
    BIO *bio = BIO_new_dgram(p->fd, BIO_NOCLOSE);
    CHECK(bio != NULL);
    CHECK(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &p->remote));
    SSL_set_bio(ssl, bio, bio);
    CHECK(SSL_set_mtu(ssl, 512));
    CHECK((p->server ? SSL_accept(ssl) : SSL_connect(ssl)) == 1);
    CHECK(SSL_version(ssl) == DTLS1_2_VERSION);
    CHECK(strcmp(SSL_get_cipher_name(ssl), p->cipher) == 0);
    CHECK(!SSL_session_reused(ssl));
    for (int i = 0; i < 4; i++) {
        if (p->server) {
            receive(ssl, request, sizeof(request)-1);
            CHECK(SSL_write(ssl, response, sizeof(response)-1) == sizeof(response)-1);
        } else {
            CHECK(SSL_write(ssl, request, sizeof(request)-1) == sizeof(request)-1);
            receive(ssl, response, sizeof(response)-1);
        }
    }
    int shutdown = SSL_shutdown(ssl);
    CHECK(shutdown >= 0);
    if (shutdown == 0) CHECK(SSL_shutdown(ssl) == 1);
    CHECK(!p->server || p->hvr == 1);
    printf("{\"mode\":\"%s\",\"server\":%d,\"version\":\"%s\",\"cipher\":\"%s\",\"sent_datagrams\":4,\"received_datagrams\":4,\"hello_verify_requests\":%d,\"mtu\":512}\n",
           p->mode, p->server, SSL_get_version(ssl), SSL_get_cipher_name(ssl), p->hvr);
    SSL_free(ssl);
    CHECK(close(p->fd) == 0);
    return NULL;
}

int main(int argc, char **argv) {
    CHECK(argc == 4 || argc == 5);
    keylog = fopen(argv[3], "wx");
    CHECK(keylog != NULL);
    const char *selected = argc == 5 ? argv[4] : "all";
    int ran = 0;
    for (int i = 0; i < 2; i++) {
        const char *mode = i ? "aes256" : "aes128";
        const char *cipher = i ? "ECDHE-RSA-AES256-GCM-SHA384" : "ECDHE-RSA-AES128-GCM-SHA256";
        if (strcmp(selected, "all") && strcmp(selected, mode)) continue;
        struct peer client = {.mode=mode, .cipher=cipher}, server = {.mode=mode, .cipher=cipher, .server=1};
        struct sockaddr_in ca, sa;
        client.fd = udp_socket(&ca, 0);
        server.fd = udp_socket(&sa, (unsigned short)(44463+i));
        client.remote = sa; server.remote = ca;
        CHECK(connect(client.fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
        CHECK(connect(server.fd, (struct sockaddr *)&ca, sizeof(ca)) == 0);
        client.ctx = context(argv[1], argv[2], cipher, 0);
        server.ctx = context(argv[1], argv[2], cipher, 1);
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, run_peer, &server) == 0);
        run_peer(&client);
        CHECK(pthread_join(thread, NULL) == 0);
        SSL_CTX_free(client.ctx); SSL_CTX_free(server.ctx);
        ran++;
    }
    CHECK(ran > 0);
    CHECK(fclose(keylog) == 0);
    return 0;
}
