//go:build ignore

// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.
// Independent OpenSSL peers. Compile explicitly with -lssl -lcrypto -lpthread;
// this program creates real TCP traffic and never imports the SDK or writes pcap.
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
#include <openssl/ech.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#endif
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failure at line %d: %s\n", __LINE__, #x); ERR_print_errors_fp(stderr); exit(1); } } while (0)
static FILE *keys;
static pthread_mutex_t print_mu = PTHREAD_MUTEX_INITIALIZER;
struct scenario {
    const char *name, *suite, *seed_suite;
    int port, version, count, matrix, attempt_early, expect_resumed, ech, reject_ech, hrr_always;
    SSL_CTX *client, *server; int listener;
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    OSSL_ECHSTORE *ech_store, *other_ech_store;
#endif
};
struct peer {
    struct scenario *scenario; int server, index, updates, requested, hrr, eoed, hellos, early_hellos;
    char early_random[65], handshake_random[65];
};

#if OPENSSL_VERSION_NUMBER >= 0x40000000L
/* Independent RFC 9850 exporter: only generator-owned ECH material and the
 * actual first ClientHello are inputs. Caller serializes writes to keys.
 * Requires <openssl/ech.h>, <openssl/pem.h>, <openssl/hmac.h> and CHECK(). */
static void emit_ech_keys(OSSL_ECHSTORE *store, const unsigned char *hello, size_t len) {
    CHECK(len >= 39 && len <= 65536 && hello[0] == 1);
    CHECK((((size_t)hello[1] << 16) | ((size_t)hello[2] << 8) | hello[3]) == len - 4);
    size_t pos = 38, n;
    pos += 1 + hello[pos]; CHECK(pos + 2 <= len);
    n = ((size_t)hello[pos] << 8) | hello[pos + 1]; pos += 2 + n; CHECK(pos < len);
    pos += 1 + hello[pos]; CHECK(pos + 2 <= len);
    n = ((size_t)hello[pos] << 8) | hello[pos + 1]; pos += 2; CHECK(n == len - pos);
    const unsigned char *ech = NULL;
    size_t ech_len = 0;
    while (pos < len) {
        CHECK(pos + 4 <= len);
        unsigned int kind = (hello[pos] << 8) | hello[pos + 1];
        n = ((size_t)hello[pos + 2] << 8) | hello[pos + 3]; pos += 4; CHECK(n <= len - pos);
        if (kind == 0xfe0d) { CHECK(ech == NULL); ech = hello + pos; ech_len = n; }
        pos += n;
    }
    CHECK(ech != NULL && ech_len >= 10 && !memcmp(ech, "\x00\x00\x01\x00\x01", 5));
    size_t enc_len = ((size_t)ech[6] << 8) | ech[7];
    if (enc_len == 0) return; /* Accepted ECH CH2 reuses the existing HPKE context. */
    CHECK(enc_len == 32 && ech_len >= 58);
    BIO *bio = BIO_new(BIO_s_mem());
    CHECK(bio && OSSL_ECHSTORE_write_pem(store, 0, bio));
    EVP_PKEY *private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    CHECK(private_key);
    char *name = NULL, *header = NULL;
    unsigned char *encoded = NULL;
    long encoded_len = 0;
    CHECK(PEM_read_bio(bio, &name, &header, &encoded, &encoded_len));
    CHECK(!strcmp(name, "ECHCONFIG") && encoded_len > 4 && encoded_len <= 1500);
    const unsigned char *config = encoded;
    size_t config_len = (size_t)encoded_len;
    /* A freshly generated store exports ECHConfigList; a PEM-loaded entry
     * exports ECHConfig. Normalize the public bytes, never the network packet. */
    if (config[0] != 0xfe || config[1] != 0x0d) {
        CHECK((((size_t)config[0] << 8) | config[1]) == config_len - 2);
        config += 2; config_len -= 2;
    }
    CHECK(config_len >= 45 && config[0] == 0xfe && config[1] == 0x0d);
    CHECK((((size_t)config[2] << 8) | config[3]) == config_len - 4);
    CHECK(config[4] == ech[5] && !memcmp(config + 5, "\x00\x20\x00\x20", 4));
    unsigned char public_key[32]; size_t public_len = sizeof(public_key);
    CHECK(EVP_PKEY_get_raw_public_key(private_key, public_key, &public_len) && public_len == 32);
    CHECK(!memcmp(public_key, config + 9, 32));
    EVP_PKEY *enc_key = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, ech + 8, 32);
    EVP_PKEY_CTX *derive = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
    unsigned char dh[32], prk[32], shared[32], zeros[32] = {0}, input[128];
    size_t dh_len = sizeof(dh); unsigned int out_len = 0;
    CHECK(enc_key && derive && EVP_PKEY_derive_init(derive) > 0);
    CHECK(EVP_PKEY_derive_set_peer(derive, enc_key) > 0);
    CHECK(EVP_PKEY_derive(derive, dh, &dh_len) > 0 && dh_len == 32);
    /* RFC 9180 DHKEM: LabeledExtract and one-block LabeledExpand. This is
     * shared_secret, not an HPKE exporter secret or a TLS traffic secret. */
    static const unsigned char kem_suite[] = {'K','E','M',0,0x20};
    pos = 0;
    memcpy(input + pos, "HPKE-v1", 7); pos += 7;
    memcpy(input + pos, kem_suite, sizeof(kem_suite)); pos += sizeof(kem_suite);
    memcpy(input + pos, "eae_prk", 7); pos += 7;
    memcpy(input + pos, dh, sizeof(dh)); pos += sizeof(dh);
    CHECK(HMAC(EVP_sha256(), zeros, sizeof(zeros), input, pos, prk, &out_len) && out_len == 32);
    pos = 0; input[pos++] = 0; input[pos++] = 32;
    memcpy(input + pos, "HPKE-v1", 7); pos += 7;
    memcpy(input + pos, kem_suite, sizeof(kem_suite)); pos += sizeof(kem_suite);
    memcpy(input + pos, "shared_secret", 13); pos += 13;
    memcpy(input + pos, ech + 8, 32); pos += 32;
    memcpy(input + pos, public_key, 32); pos += 32;
    input[pos++] = 1;
    CHECK(HMAC(EVP_sha256(), prk, sizeof(prk), input, pos, shared, &out_len) && out_len == 32);
    CHECK(fputs("ECH_SECRET ", keys) >= 0);
    for (size_t i = 6; i < 38; i++) CHECK(fprintf(keys, "%02x", hello[i]) == 2);
    CHECK(fputc(' ', keys) != EOF);
    for (size_t i = 0; i < sizeof(shared); i++) CHECK(fprintf(keys, "%02x", shared[i]) == 2);
    CHECK(fputs("\nECH_CONFIG ", keys) >= 0);
    for (size_t i = 6; i < 38; i++) CHECK(fprintf(keys, "%02x", hello[i]) == 2);
    CHECK(fputc(' ', keys) != EOF);
    for (size_t i = 0; i < config_len; i++) CHECK(fprintf(keys, "%02x", config[i]) == 2);
    CHECK(fputc('\n', keys) != EOF && fflush(keys) == 0);
    EVP_PKEY_CTX_free(derive); EVP_PKEY_free(enc_key); EVP_PKEY_free(private_key);
    BIO_free(bio); OPENSSL_free(name); OPENSSL_free(header); OPENSSL_free(encoded);
    OPENSSL_cleanse(dh, sizeof(dh)); OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(shared, sizeof(shared)); OPENSSL_cleanse(input, sizeof(input));
}
#endif

static void keylog(const SSL *ssl, const char *line) {
    struct peer *p = SSL_get_app_data(ssl);
    const char *early = "CLIENT_EARLY_TRAFFIC_SECRET ", *handshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET ";
    if (p && !strncmp(line, early, strlen(early))) { CHECK(strlen(line) >= strlen(early) + 64); memcpy(p->early_random, line + strlen(early), 64); }
    if (p && !strncmp(line, handshake, strlen(handshake))) { CHECK(strlen(line) >= strlen(handshake) + 64); memcpy(p->handshake_random, line + strlen(handshake), 64); }
    pthread_mutex_lock(&print_mu);
    CHECK(fprintf(keys, "%s\n", line) > 0); fflush(keys);
    pthread_mutex_unlock(&print_mu);
}
static int early_mode(const struct scenario *s) { return !strcmp(s->name, "early") || !strcmp(s->name, "hrr_early") || s->attempt_early; }
static int retry_attempt(const struct scenario *s, int index) { return index > 0 && (s->matrix || (s->ech && !s->reject_ech) || !strcmp(s->name, "hrr_early")); }
static int resumed(const struct scenario *s, int index) { return index > 0 && (s->matrix || s->ech ? s->expect_resumed : strcmp(s->name, "hrr_early") != 0); }
static int hello_early(const unsigned char *b, size_t len) {
    size_t pos = 38; CHECK(pos < len);
    pos += 1 + b[pos]; CHECK(pos + 2 <= len);
    size_t n = ((size_t)b[pos] << 8) | b[pos + 1]; pos += 2 + n; CHECK(pos < len);
    pos += 1 + b[pos]; CHECK(pos + 2 <= len);
    n = ((size_t)b[pos] << 8) | b[pos + 1]; pos += 2; CHECK(n == len - pos);
    int early = 0;
    while (pos < len) {
        CHECK(pos + 4 <= len);
        int kind = (b[pos] << 8) | b[pos + 1];
        n = ((size_t)b[pos + 2] << 8) | b[pos + 3]; pos += 4; CHECK(n <= len - pos);
        if (kind == 42) { CHECK(n == 0); early++; }
        pos += n;
    }
    CHECK(early <= 1); return early;
}
static void message(int write, int version, int type, const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)arg;
    struct peer *p = SSL_get_app_data(ssl);
    const unsigned char *b = buf;
    static const unsigned char retry_random[32] = {
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
    if (!p || !write || type != SSL3_RT_HANDSHAKE || len < 4) return;
    if (b[0] == 24) {
        CHECK(len == 5 && b[4] < 2);
        p->updates++; p->requested += b[4];
        pthread_mutex_lock(&print_mu);
        printf("{\"event\":\"key_update\",\"mode\":\"%s\",\"server\":%d,\"requested\":%d}\n", p->scenario->name, p->server, b[4]);
        pthread_mutex_unlock(&print_mu);
    }
    if (b[0] == 1) {
        p->hellos++; p->early_hellos += hello_early(b, len);
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
        if (p->scenario->ech && !p->server && p->hellos == 1) {
            pthread_mutex_lock(&print_mu); emit_ech_keys(p->scenario->ech_store, b, len); pthread_mutex_unlock(&print_mu);
        }
#endif
        /* RFC 9849 allows an accepted ECH CH2 Outer to copy early_data;
         * the independent HPKE/API checks require Inner2 to remove it. */
        if (p->hellos == 2 && !p->scenario->ech) CHECK(!hello_early(b, len));
    }
    if (b[0] == 5) p->eoed++;
    if (b[0] == 2 && len >= 38 && !memcmp(b + 6, retry_random, 32)) p->hrr++;
}
static int allow_early(SSL *ssl, void *arg) {
    (void)arg;
    struct peer *p = SSL_get_app_data(ssl);
    return p->scenario->matrix || p->scenario->ech || !strcmp(p->scenario->name, "hrr_early") || p->index == 2; /* Seed, resumed, accepted, deliberately rejected. */
}
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
static OSSL_ECHSTORE *new_ech_store(void) {
    OSSL_ECHSTORE *generated = OSSL_ECHSTORE_new(NULL, NULL), *loaded = OSSL_ECHSTORE_new(NULL, NULL);
    OSSL_HPKE_SUITE hpke = OSSL_HPKE_SUITE_DEFAULT;
    BIO *pem = BIO_new(BIO_s_mem()); CHECK(generated && loaded && pem);
    CHECK(OSSL_ECHSTORE_new_config(generated, OSSL_ECH_CURRENT_VERSION, 0, "public.example", hpke));
    /* Load the serialized configuration through the public PEM path, which
     * supplies a single canonical ECHConfig to HPKE, not its list prefix. */
    CHECK(OSSL_ECHSTORE_write_pem(generated, 0, pem));
    CHECK(OSSL_ECHSTORE_read_pem(loaded, pem, 1));
    BIO_free(pem); OSSL_ECHSTORE_free(generated); return loaded;
}
#endif
static int ech_status(SSL *ssl, struct peer *p) {
    (void)ssl; (void)p;
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    if (p->scenario->ech) {
        char *inner = NULL, *outer = NULL;
        int status = SSL_ech_get1_status(ssl, &inner, &outer);
        OPENSSL_free(inner); OPENSSL_free(outer); return status;
    }
#endif
    return 0;
}
static const unsigned char grease[] = {
    0, 0,1, 0,1, 42, 0,32,
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
    0,32, 41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,
    57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72
};
static int add_grease(SSL *ssl, unsigned int ext, const unsigned char **out, size_t *len, int *alert, void *arg) {
    (void)ssl; (void)ext; (void)alert; (void)arg;
    *out = grease; *len = sizeof(grease); return 1;
}
static void configure(struct scenario *s, const char *cert, const char *key) {
    s->client = SSL_CTX_new(TLS_client_method()); s->server = SSL_CTX_new(TLS_server_method());
    CHECK(s->client && s->server);
    SSL_CTX *contexts[] = {s->client, s->server};
    for (int i = 0; i < 2; i++) {
        CHECK(SSL_CTX_set_min_proto_version(contexts[i], s->version));
        CHECK(SSL_CTX_set_max_proto_version(contexts[i], s->version));
        CHECK(SSL_CTX_set1_groups_list(contexts[i], "X25519:P-256"));
        const char *suite = s->seed_suite ? s->seed_suite : s->suite;
        CHECK(s->version == TLS1_3_VERSION ? SSL_CTX_set_ciphersuites(contexts[i], suite) : SSL_CTX_set_cipher_list(contexts[i], suite));
        SSL_CTX_set_msg_callback(contexts[i], message);
    }
    CHECK(SSL_CTX_use_certificate_chain_file(s->server, cert));
    CHECK(SSL_CTX_use_PrivateKey_file(s->server, key, SSL_FILETYPE_PEM));
    CHECK(SSL_CTX_check_private_key(s->server));
    SSL_CTX_set_verify(s->client, SSL_VERIFY_NONE, NULL); /* Ephemeral loopback certificate. */
    SSL_CTX_set_keylog_callback(s->client, keylog);
    CHECK(SSL_CTX_set_session_id_context(s->server, (const unsigned char *)"d10", 3));
    SSL_CTX_set_session_cache_mode(s->server, SSL_SESS_CACHE_SERVER);
    if (s->version == TLS1_3_VERSION) CHECK(SSL_CTX_set_num_tickets(s->server, 1));
    if (!strcmp(s->name, "hrr")) CHECK(SSL_CTX_set1_groups_list(s->server, "P-256"));
    if (s->hrr_always) CHECK(SSL_CTX_set1_groups_list(s->server, "P-256"));
    if (early_mode(s)) {
        CHECK(SSL_CTX_set_max_early_data(s->server, 4096));
        SSL_CTX_set_allow_early_data_cb(s->server, allow_early, NULL);
    }
    if (s->seed_suite) {
        char offered[128]; CHECK(snprintf(offered, sizeof(offered), "%s:%s", s->seed_suite, s->suite) < (int)sizeof(offered));
        CHECK(SSL_CTX_set_ciphersuites(s->client, offered));
    }
    if (!strcmp(s->name, "grease")) CHECK(SSL_CTX_add_client_custom_ext(s->client, 0xfe0d, add_grease, NULL, NULL, NULL, NULL));
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    if (s->ech) {
        CHECK(SSL_CTX_load_verify_locations(s->client, cert, NULL));
        SSL_CTX_set_verify(s->client, SSL_VERIFY_PEER, NULL);
        s->ech_store = new_ech_store(); s->other_ech_store = new_ech_store();
        CHECK(SSL_CTX_set1_echstore(s->client, s->ech_store));
        CHECK(SSL_CTX_set1_echstore(s->server, s->ech_store));
        SSL_CTX_set_keylog_callback(s->server, keylog); /* Rejected client may stop before exporting app keys. */
        if (s->attempt_early) {
            CHECK(SSL_CTX_set_recv_max_early_data(s->server, 4096));
            /* This single-use loopback fixture isolates PSK/HRR from server
             * replay policy; it is not advice for a production server. */
            SSL_CTX_set_options(s->server, SSL_OP_NO_ANTI_REPLAY);
        }
    }
#endif
}
static int socket_for(int port, int listen_mode) {
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    CHECK(fd >= 0);
    CHECK(!setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));
    struct timeval timeout = {.tv_sec = 10};
    CHECK(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    CHECK(!setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (listen_mode) {
        CHECK(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
        CHECK(!bind(fd, (struct sockaddr *)&addr, sizeof(addr))); CHECK(!listen(fd, 1));
    } else CHECK(!connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
    return fd;
}
static size_t http_message(char *out, size_t cap, const char *mode, int index, int response) {
    if (!response) return (size_t)snprintf(out, cap, "GET /d10/%s/%d HTTP/1.1\r\nHost: fixture\r\n\r\n", mode, index);
    char body[128]; int n = snprintf(body, sizeof(body), "d10/%s/%d\n", mode, index);
    return (size_t)snprintf(out, cap, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", n, body);
}
static void send_bytes(SSL *ssl, const char *data, size_t len) {
    /* Fragment HTTP headers across authenticated TLS records. */
    size_t first = len > 3 ? 3 : len, done;
    CHECK(SSL_write_ex(ssl, data, first, &done) && done == first);
    if (len > first) CHECK(SSL_write_ex(ssl, data + first, len - first, &done) && done == len - first);
}
static void receive_bytes(SSL *ssl, const char *want, size_t len) {
    char buf[1024]; size_t pos = 0, got;
    CHECK(len <= sizeof(buf));
    while (pos < len) { CHECK(SSL_read_ex(ssl, buf + pos, len - pos, &got) && got); pos += got; }
    CHECK(!memcmp(buf, want, len));
}
static void report(SSL *ssl, struct peer *p) {
    pthread_mutex_lock(&print_mu);
    printf("{\"event\":\"connection\",\"mode\":\"%s\",\"index\":%d,\"server\":%d,\"version\":\"%s\",\"cipher\":\"%s\",\"resumed\":%d,\"early_status\":%d,\"sent_key_updates\":%d,\"requested_updates\":%d,\"sent_hrr\":%d,\"sent_eoed\":%d,\"sent_client_hellos\":%d,\"early_client_hellos\":%d,\"ech_status\":%d}\n",
        p->scenario->name, p->index, p->server, SSL_get_version(ssl), SSL_get_cipher_name(ssl), SSL_session_reused(ssl), SSL_get_early_data_status(ssl), p->updates, p->requested, p->hrr, p->eoed, p->hellos, p->early_hellos, ech_status(ssl, p));
    fflush(stdout); pthread_mutex_unlock(&print_mu);
}
static void close_tls(SSL *ssl, int fd) { int result = SSL_shutdown(ssl); CHECK(result >= 0); if (!result) CHECK(SSL_shutdown(ssl) == 1); SSL_free(ssl); close(fd); }
static void exchange(SSL *ssl, struct peer *p, const char *early, size_t early_len) {
    int updates = !strncmp(p->scenario->name, "ku_", 3);
    int rounds = updates ? 6 : 1;
    for (int i = 0; i < rounds; i++) {
        int index = updates ? i : p->index;
        char request[512], response[512];
        size_t nr = http_message(request, sizeof(request), p->scenario->name, index, 0);
        size_t ns = http_message(response, sizeof(response), p->scenario->name, index, 1);
        if (p->server) {
            if (early_len) { CHECK(early_len == nr && !memcmp(early, request, nr)); early_len = 0; }
            else receive_bytes(ssl, request, nr);
            if (updates && (i == 2 || i == 4)) CHECK(SSL_key_update(ssl, i == 2 ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED));
            send_bytes(ssl, response, ns);
        } else {
            if (updates && (i == 1 || i == 3 || i == 5)) CHECK(SSL_key_update(ssl, i == 3 ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED));
            if (!early_len || SSL_get_early_data_status(ssl) != SSL_EARLY_DATA_ACCEPTED) send_bytes(ssl, request, nr);
            receive_bytes(ssl, response, ns);
        }
    }
    if (updates) CHECK(p->updates >= 3 && p->requested >= 1);
}
static void *serve(void *arg) {
    struct scenario *s = arg;
    for (int i = 0; i < s->count; i++) {
        int fd = accept(s->listener, NULL, NULL); CHECK(fd >= 0);
        struct peer p = {.scenario = s, .server = 1, .index = i};
        SSL *ssl = SSL_new(s->server); CHECK(ssl && SSL_set_fd(ssl, fd)); SSL_set_app_data(ssl, &p);
        if (retry_attempt(s, i)) CHECK(SSL_set1_groups_list(ssl, "P-256"));
        if (s->seed_suite && i > 0) CHECK(SSL_set_ciphersuites(ssl, s->suite));
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
        if (s->reject_ech && i > 0) CHECK(SSL_set1_echstore(ssl, s->other_ech_store));
#endif
        char early[4096]; size_t used = 0;
        if (early_mode(s)) {
            size_t got; int result;
            do { result = SSL_read_early_data(ssl, early + used, sizeof(early) - used, &got); CHECK(result != SSL_READ_EARLY_DATA_ERROR); used += got; } while (result == SSL_READ_EARLY_DATA_SUCCESS);
        }
        int result = SSL_accept(ssl);
        if (s->reject_ech && i > 0) {
            CHECK(result != 1 && p.hrr == 0 && used == 0 && SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_REJECTED);
            CHECK(ech_status(ssl, &p) != 1); report(ssl, &p); SSL_free(ssl); close(fd); continue;
        }
        CHECK(result == 1);
        if (s->ech) CHECK(ech_status(ssl, &p) == 1);
        CHECK(SSL_session_reused(ssl) == resumed(s, i));
        CHECK(!strcmp(SSL_get_cipher_name(ssl), s->seed_suite && i == 0 ? s->seed_suite : s->suite));
        if (!strcmp(s->name, "early") && i >= 2) CHECK(SSL_get_early_data_status(ssl) == (i == 2 ? SSL_EARLY_DATA_ACCEPTED : SSL_EARLY_DATA_REJECTED));
        if (!strcmp(s->name, "hrr")) CHECK(p.hrr == 1);
        if (!strcmp(s->name, "hrr_early") || s->matrix || s->ech) {
            CHECK(p.hrr == (s->hrr_always || retry_attempt(s, i))); CHECK(used == 0);
            if (i > 0 && early_mode(s)) CHECK(SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_REJECTED);
        }
        exchange(ssl, &p, early, used); report(ssl, &p); close_tls(ssl, fd);
    }
    return NULL;
}
static void run(struct scenario *s, const char *cert, const char *key) {
    configure(s, cert, key); s->listener = socket_for(s->port, 1);
    pthread_t thread; CHECK(!pthread_create(&thread, NULL, serve, s));
    SSL_SESSION *session = NULL;
    for (int i = 0; i < s->count; i++) {
        int fd = socket_for(s->port, 0); SSL *ssl = SSL_new(s->client); CHECK(ssl && SSL_set_fd(ssl, fd));
        struct peer p = {.scenario = s, .index = i}; SSL_set_app_data(ssl, &p);
        CHECK(SSL_set_tlsext_host_name(ssl, (s->ech ? "secret.example" : "localhost")));
        if (session) CHECK(SSL_set_session(ssl, session));
        char early[512]; size_t n = 0, written;
        if ((!strcmp(s->name, "early") && i >= 2) || (retry_attempt(s, i) && early_mode(s)) || (s->reject_ech && i > 0)) {
            CHECK(session && SSL_SESSION_get_max_early_data(session) >= sizeof(early));
            n = http_message(early, sizeof(early), s->name, i, 0);
            CHECK(SSL_write_early_data(ssl, early, n, &written) && written == n);
        }
        int result = SSL_connect(ssl);
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
        if (s->reject_ech && i > 0) {
            CHECK(result != 1 && ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_ECH_REQUIRED);
            CHECK(p.hellos == 1 && p.early_hellos == 1 && p.eoed == 0);
            CHECK(p.early_random[0] && p.handshake_random[0] && strcmp(p.early_random, p.handshake_random));
            CHECK(SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_REJECTED);
            report(ssl, &p); SSL_free(ssl); close(fd); continue;
        }
#endif
        CHECK(result == 1); CHECK(SSL_session_reused(ssl) == resumed(s, i));
        if (s->ech) CHECK(ech_status(ssl, &p) == 1);
        CHECK(!strcmp(SSL_get_cipher_name(ssl), s->seed_suite && i == 0 ? s->seed_suite : s->suite));
        if (n) CHECK(SSL_get_early_data_status(ssl) == (!strcmp(s->name, "early") && i == 2 ? SSL_EARLY_DATA_ACCEPTED : SSL_EARLY_DATA_REJECTED));
        if (!strcmp(s->name, "hrr_early") || s->matrix || s->ech) {
            CHECK(p.hellos == (s->hrr_always || retry_attempt(s, i) ? 2 : 1));
            CHECK(p.early_hellos == (i > 0 && early_mode(s) ? (s->ech ? 2 : 1) : 0)); CHECK(p.eoed == 0);
        }
        exchange(ssl, &p, early, n); report(ssl, &p);
        SSL_SESSION_free(session); session = SSL_get1_session(ssl); CHECK(session);
        close_tls(ssl, fd);
    }
    SSL_SESSION_free(session); CHECK(!pthread_join(thread, NULL)); close(s->listener);
    SSL_CTX_free(s->client); SSL_CTX_free(s->server);
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    OSSL_ECHSTORE_free(s->ech_store); OSSL_ECHSTORE_free(s->other_ech_store);
#endif
}
int main(int argc, char **argv) {
    CHECK(argc == 4 || argc == 5); signal(SIGPIPE, SIG_IGN); umask(077);
    keys = fopen(argv[3], "wx"); CHECK(keys);
    const char *mode = argc == 5 ? argv[4] : "all";
    struct scenario scenarios[] = {
        {.name="ku_aes128", .suite="TLS_AES_128_GCM_SHA256", .port=44454, .version=TLS1_3_VERSION, .count=1},
        {.name="ku_aes256", .suite="TLS_AES_256_GCM_SHA384", .port=44455, .version=TLS1_3_VERSION, .count=1},
        {.name="ku_chacha", .suite="TLS_CHACHA20_POLY1305_SHA256", .port=44456, .version=TLS1_3_VERSION, .count=1},
        {.name="hrr", .suite="TLS_AES_128_GCM_SHA256", .port=44457, .version=TLS1_3_VERSION, .count=1},
        {.name="early", .suite="TLS_AES_128_GCM_SHA256", .port=44458, .version=TLS1_3_VERSION, .count=4},
        {.name="tls12_resume", .suite="ECDHE-RSA-AES256-GCM-SHA384", .port=44459, .version=TLS1_2_VERSION, .count=2},
        {.name="hrr_early", .suite="TLS_AES_128_GCM_SHA256", .port=44475, .version=TLS1_3_VERSION, .count=2},
        {.name="grease", .suite="TLS_AES_128_GCM_SHA256", .port=44462, .version=TLS1_3_VERSION, .count=1},
        {.name="hrr_early_aes128", .suite="TLS_AES_128_GCM_SHA256", .port=44482, .version=TLS1_3_VERSION, .count=2, .matrix=1, .attempt_early=1, .expect_resumed=0},
        {.name="hrr_early_aes256", .suite="TLS_AES_256_GCM_SHA384", .port=44483, .version=TLS1_3_VERSION, .count=2, .matrix=1, .attempt_early=1, .expect_resumed=0},
        {.name="hrr_early_chacha", .suite="TLS_CHACHA20_POLY1305_SHA256", .port=44484, .version=TLS1_3_VERSION, .count=2, .matrix=1, .attempt_early=1, .expect_resumed=0},
        {.name="hrr_psk_aes128", .suite="TLS_AES_128_GCM_SHA256", .port=44485, .version=TLS1_3_VERSION, .count=2, .matrix=1, .expect_resumed=1},
        {.name="hrr_psk_aes256", .suite="TLS_AES_256_GCM_SHA384", .port=44486, .version=TLS1_3_VERSION, .count=2, .matrix=1, .expect_resumed=1},
        {.name="hrr_psk_chacha", .suite="TLS_CHACHA20_POLY1305_SHA256", .port=44487, .version=TLS1_3_VERSION, .count=2, .matrix=1, .expect_resumed=1},
        {.name="hrr_early_switch_chacha", .seed_suite="TLS_AES_128_GCM_SHA256", .suite="TLS_CHACHA20_POLY1305_SHA256", .port=44488, .version=TLS1_3_VERSION, .count=2, .matrix=1, .attempt_early=1, .expect_resumed=0},
        {.name="hrr_early_switch_aes256", .seed_suite="TLS_AES_128_GCM_SHA256", .suite="TLS_AES_256_GCM_SHA384", .port=44489, .version=TLS1_3_VERSION, .count=2, .matrix=1, .attempt_early=1, .expect_resumed=0},
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
        {.name="ech_hrr_aes128", .suite="TLS_AES_128_GCM_SHA256", .port=44490, .version=TLS1_3_VERSION, .count=1, .ech=1, .hrr_always=1},
        {.name="ech_hrr_aes256", .suite="TLS_AES_256_GCM_SHA384", .port=44491, .version=TLS1_3_VERSION, .count=1, .ech=1, .hrr_always=1},
        {.name="ech_hrr_chacha", .suite="TLS_CHACHA20_POLY1305_SHA256", .port=44492, .version=TLS1_3_VERSION, .count=1, .ech=1, .hrr_always=1},
        {.name="ech_hrr_early_aes128", .suite="TLS_AES_128_GCM_SHA256", .port=44493, .version=TLS1_3_VERSION, .count=2, .ech=1, .attempt_early=1, .expect_resumed=1},
        {.name="ech_hrr_early_aes256", .suite="TLS_AES_256_GCM_SHA384", .port=44494, .version=TLS1_3_VERSION, .count=2, .ech=1, .attempt_early=1, .expect_resumed=1},
        {.name="ech_hrr_early_chacha", .suite="TLS_CHACHA20_POLY1305_SHA256", .port=44495, .version=TLS1_3_VERSION, .count=2, .ech=1, .attempt_early=1, .expect_resumed=1},
        {.name="ech_rejected_early_aes128", .suite="TLS_AES_128_GCM_SHA256", .port=44496, .version=TLS1_3_VERSION, .count=2, .ech=1, .attempt_early=1, .reject_ech=1}
#endif
    };
    int selected = 0;
    for (size_t i = 0; i < sizeof(scenarios)/sizeof(scenarios[0]); i++) if ((!strcmp(mode, "all") && !scenarios[i].matrix && !scenarios[i].ech) || (!strcmp(mode, "matrix") && scenarios[i].matrix) || (!strcmp(mode, "ech-matrix") && scenarios[i].ech) || !strcmp(mode, scenarios[i].name)) { run(&scenarios[i], argv[1], argv[2]); selected++; }
    CHECK(selected); CHECK(!fclose(keys)); return 0;
}
