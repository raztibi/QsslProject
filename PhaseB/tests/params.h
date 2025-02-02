#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib") // Link with Winsock library

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include <oqs/oqs.h>

/* Volatile pointer to prevent compiler optimization from removing the memset */
static void* (* const volatile memset_secure)(void*, int, size_t) = memset;

static void secure_memzero(void* ptr, size_t len) {
    if (ptr == NULL) {
        return;
    }
    /* Use volatile function pointer to prevent optimization */
    memset_secure(ptr, 0, len);
}

/* Macro to safely clear AES key material */
#define SAFE_AES_KEY_MEMSET(ptr) do { \
    if ((ptr) != NULL) { \
        secure_memzero((ptr), AES_KEY_SIZE); \
    } \
} while(0)

#define AES_KEY_SIZE 32  // 256 bits
#define AES_BLOCK_SIZE 16
#define MAX_DATA_SIZE 1024
#define RSA_KEY_SIZE 2048

#if defined(OPENSSL_VERSION)

// declare once to allow implement server and client functions
#define CLIENT_IMPLEMENTATION
#define SERVER_IMPLEMENTATION


#else /* OPENSSL_VERSION_NUMBER */
#error "OpenSSL is required for this implementation"
#endif /* OPENSSL_VERSION_NUMBER */

static void handle_openssl_error() {
    exit(1);
}
