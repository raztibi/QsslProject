#pragma once
#include "crypto_functions.h"
#include "socket_functions.h"

// Forward declarations of structs
typedef struct Client Client;

// Function pointer typedefs
typedef void (*ClientCleanupFunc)(Client* client);

struct Client {
    // Data members
    EC_KEY* ecc_private_key; // For signing
    EC_KEY* ecc_public_key;  // For verification
    uint8_t dilithium_private_key[OQS_SIG_dilithium_2_length_secret_key];
    uint8_t dilithium_public_key[OQS_SIG_dilithium_2_length_public_key];

    BOOL is_initialized;

    // Generate AES key
    unsigned char aes_key[AES_KEY_SIZE];

    ClientCleanupFunc cleanup;
};

typedef struct Server_Keys {
    RSA* rsa_public_key;
    EC_KEY* ecc_public_key;
    uint8_t kyber_public_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t dilithium_public_key[OQS_SIG_dilithium_2_length_public_key];
}Server_Keys;