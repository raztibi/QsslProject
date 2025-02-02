#pragma once
#include "crypto_functions.h"
#include "socket_functions.h"

// Forward declarations of structs
typedef struct Server Server;

// Function pointer typedefs
typedef void (*ServerCleanupFunc)(Server* server);

struct Server {
    // Data members
    RSA* rsa_private_key;
    RSA* rsa_public_key;
    EC_KEY* ecc_private_key;
    EC_KEY* ecc_public_key;
    uint8_t kyber_private_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t kyber_public_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t kyber_shared_secret[OQS_KEM_kyber_768_length_shared_secret];
    uint8_t dilithium_private_key[OQS_SIG_dilithium_2_length_secret_key];
    uint8_t dilithium_public_key[OQS_SIG_dilithium_2_length_public_key];

    BOOL is_initialized;

    ServerCleanupFunc cleanup;
};

typedef struct Client_Keys {
    EC_KEY* ecc_public_key;
    uint8_t dilithium_public_key[OQS_SIG_dilithium_2_length_public_key];
}Client_Keys;
