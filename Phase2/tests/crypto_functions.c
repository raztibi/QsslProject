#include "crypto_functions.h"

#pragma region ECC Functions

 BOOL ecc_verify (EC_KEY* verify_key, unsigned char* message, size_t message_len, unsigned char* signature, unsigned int sig_len) 
 {
    // Calculate hash of the encrypted AES key
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, message_len);
    SHA256_Final(hash, &sha256);

    // Create signature object and set r,s values
    ECDSA_SIG* ecc_sig = ECDSA_SIG_new();
    if (!ecc_sig) {
        return FALSE;
    }

    BIGNUM* r = BN_bin2bn(signature, sig_len / 2, NULL);
    BIGNUM* s = BN_bin2bn(signature + sig_len / 2, sig_len / 2, NULL);

    if (!r || !s) {
        ECDSA_SIG_free(ecc_sig);
        BN_free(r);
        BN_free(s);
        return FALSE;
    }

    ECDSA_SIG_set0(ecc_sig, r, s);

    // Verify the signature using the public ECC key
    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, ecc_sig, verify_key);
    ECDSA_SIG_free(ecc_sig);

    return (result == 1) ? TRUE : FALSE;
}

 BOOL ecc_sign (EC_KEY* sign_key, unsigned char* message, size_t message_len, unsigned char* signature, unsigned int* sig_len) 
 {
     unsigned char hash[SHA256_DIGEST_LENGTH];
     SHA256_CTX sha256;
     SHA256_Init(&sha256);
     SHA256_Update(&sha256, message, message_len);
     SHA256_Final(hash, &sha256);

     ECDSA_SIG* ecc_sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, sign_key);
     if (!ecc_sig) {
         return FALSE;
     }

     const BIGNUM* r, * s;
     ECDSA_SIG_get0(ecc_sig, &r, &s);

     *sig_len = BN_num_bytes(r) + BN_num_bytes(s);
     BN_bn2bin(r, signature);
     BN_bn2bin(s, signature + BN_num_bytes(r));

     ECDSA_SIG_free(ecc_sig);
     return TRUE;
 }

 // Serialize EC public key to PEM format
 char* serialize_ecc_key(EC_KEY* ecc_public_key, size_t* key_len) {
     BIO* bio = BIO_new(BIO_s_mem());
     if (!bio) {
         fprintf(stderr, "Failed to create BIO\n");
         return NULL;
     }

     if (!PEM_write_bio_EC_PUBKEY(bio, ecc_public_key)) {
         fprintf(stderr, "Failed to write EC public key to BIO\n");
         BIO_free(bio);
         return NULL;
     }

     char* key_data;
     *key_len = BIO_get_mem_data(bio, &key_data);

     char* serialized_key = malloc(*key_len);
     if (!serialized_key) {
         perror("malloc");
         BIO_free(bio);
         return NULL;
     }

     memcpy(serialized_key, key_data, *key_len);
     BIO_free(bio);

     return serialized_key;
 }

 // Deserialize EC public key from given key_data
 EC_KEY* deserialize_ecc_key(const char* key_data, size_t key_len) {
     BIO* bio = BIO_new_mem_buf(key_data, (int)key_len);
     if (!bio) {
         fprintf(stderr, "Failed to create BIO\n");
         return NULL;
     }

     EC_KEY* ecc_public_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
     if (!ecc_public_key) {
         fprintf(stderr, "Failed to deserialize EC public key\n");
         BIO_free(bio);
         return NULL;
     }

     BIO_free(bio);
     return ecc_public_key;
 }

 // Generate ECC key pair
 int generate_ecc_keys(EC_KEY** ecc_private_key, EC_KEY** ecc_public_key) {
     *ecc_private_key = EC_KEY_new_by_curve_name(NID_secp256k1);
     if (!*ecc_private_key) {
         handle_openssl_error();
         return FALSE;
     }

     if (!EC_KEY_generate_key(*ecc_private_key)) {
         handle_openssl_error();
         return FALSE;
     }

     *ecc_public_key = EC_KEY_new_by_curve_name(NID_secp256k1);
     if (!*ecc_public_key) {
         handle_openssl_error();
         return FALSE;
     }

     const EC_POINT* pub_key = EC_KEY_get0_public_key(*ecc_private_key);
     if (!EC_KEY_set_public_key(*ecc_public_key, pub_key)) {
         handle_openssl_error();
         return FALSE;
     }
     return TRUE;
 }

#pragma endregion

#pragma region RSA Functions

BOOL rsa_encrypt(RSA* rsa_enc_key, unsigned char* message, size_t message_len, unsigned char* ciphertext, size_t* ciphertext_len)
{
    int result = RSA_public_encrypt(message_len, message, ciphertext, rsa_enc_key, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        return FALSE;
    }

    *ciphertext_len = result;
    return TRUE;
}

BOOL rsa_decrypt(RSA* rsa_dec_key, unsigned char* ciphertext, size_t cipher_len, unsigned char* plaintext, size_t* plaintext_len)
{
    int result = RSA_private_decrypt(cipher_len, ciphertext, plaintext, rsa_dec_key, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        return FALSE;
    }

    *plaintext_len = result;
    return TRUE;
}

// Serialize RSA public key to PEM format
char* serialize_rsa_key(RSA* rsa_public_key, size_t* key_len) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        handle_openssl_error();
    }

    if (!PEM_write_bio_RSA_PUBKEY(bio, rsa_public_key)) {
        handle_openssl_error();
    }

    // Get the key data
    char* key_data;
    *key_len = BIO_get_mem_data(bio, &key_data);

    // Allocate memory for the serialized key
    char* serialized_key = malloc(*key_len);
    if (!serialized_key) {
        perror("malloc");
        BIO_free(bio);
        return NULL;
    }

    memcpy(serialized_key, key_data, *key_len);
    BIO_free(bio);

    return serialized_key;
}

// Deserialize RSA public key from given key_data
RSA* deserialize_rsa_key(const char* key_data, size_t key_len) {
    BIO* bio = BIO_new_mem_buf(key_data, (int)key_len);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        return NULL;
    }

    RSA* rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa_public_key) {
        fprintf(stderr, "Failed to deserialize public key\n");
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return rsa_public_key;
}

// Generate RSA key pair
int generate_rsa_keys(RSA** rsa_private_key, RSA** rsa_public_key) {
    BIGNUM* bn = BN_new();
    if (!BN_set_word(bn, RSA_F4)) {
        handle_openssl_error();
        return FALSE;
    }

    *rsa_private_key = RSA_new();
    if (!RSA_generate_key_ex(*rsa_private_key, RSA_KEY_SIZE, bn, NULL)) {
        handle_openssl_error();
        return FALSE;
    }

    // Extract public key
    *rsa_public_key = RSAPublicKey_dup(*rsa_private_key);
    if (*rsa_public_key == NULL) {
        handle_openssl_error();
        return FALSE;
    }

    BN_free(bn);
    return TRUE;
}

#pragma endregion

#pragma region AES Functions

BOOL aes_encrypt(unsigned char* enc_key, unsigned char* plaintext, size_t plaintext_len, unsigned char* iv,
    unsigned char* ciphertext, size_t* cipher_len)
{
    AES_KEY aes;
    if (AES_set_encrypt_key(enc_key, AES_KEY_SIZE * 8, &aes) < 0) {
        return FALSE;
    }

    size_t padded_len = ((plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    unsigned char* padded_data = (unsigned char*)malloc(padded_len);
    if (!padded_data) {
        return FALSE;
    }

    memcpy(padded_data, plaintext, plaintext_len);
    size_t padding_len = padded_len - plaintext_len;
    memset(padded_data + plaintext_len, padding_len, padding_len);

    unsigned char temp_iv[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        AES_cbc_encrypt(padded_data + i, ciphertext + i,
            AES_BLOCK_SIZE, &aes, temp_iv, AES_ENCRYPT);
    }

    free(padded_data);
    *cipher_len = padded_len;
    return TRUE;
}

BOOL aes_decrypt(unsigned char* dec_key, unsigned char* ciphertext, size_t cipher_len, unsigned char* iv,
    unsigned char* plaintext, size_t* plaintext_len)
{
    AES_KEY aes;
    if (AES_set_decrypt_key(dec_key, AES_KEY_SIZE * 8, &aes) < 0) {
        return FALSE;
    }

    unsigned char temp_iv[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);

    // Decrypt all blocks
    for (size_t i = 0; i < cipher_len; i += AES_BLOCK_SIZE) {
        AES_cbc_encrypt(ciphertext + i, plaintext + i, AES_BLOCK_SIZE, &aes, temp_iv, AES_DECRYPT);
    }

    // Remove padding
    unsigned char padding_len = plaintext[cipher_len - 1];
    *plaintext_len = cipher_len - padding_len;

    return TRUE;
}

int generate_aes_key(unsigned char* key, int key_len) {
   
    if (!RAND_bytes(key, key_len)) {
        handle_openssl_error();
        return FALSE;
    }
    return TRUE;
}

#pragma endregion

#pragma region Kyber Functions

// Generate Kyber key pair
int generate_kyber_keys(uint8_t* kyber_secret_key, uint8_t* kyber_public_key)
{
#ifndef OQS_ENABLE_KEM_kyber_768 // if Kyber-768 was not enabled at compile-time
    printf("[generate_kyber_keys] OQS_KEM_kyber_768 was not enabled at "
        "compile-time.\n");
    return FALSE; // nothing done successfully ;-)
#else
    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(kyber_public_key, kyber_secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
        OQS_MEM_cleanse(kyber_secret_key, OQS_KEM_kyber_768_length_secret_key);
        return FALSE;
    }
    return TRUE;
#endif
}

// Encapsulate given public key and create shared secret and encapsulated data
int kyber_encapsulate(uint8_t* encapsulated_data, uint8_t* shared_secret, uint8_t* kyber_public_key) {
#ifndef OQS_ENABLE_KEM_kyber_768 // if Kyber-768 was not enabled at compile-time
    printf("[kyber_encapsulate] OQS_KEM_kyber_768 was not enabled at "
        "compile-time.\n");
    return FALSE; // nothing done successfully ;-)
#else
    OQS_STATUS rc = OQS_KEM_kyber_768_encaps(encapsulated_data, shared_secret, kyber_public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
        OQS_MEM_cleanse(shared_secret, OQS_KEM_kyber_768_length_shared_secret);
        return FALSE;
    }
    return TRUE;
#endif
}

// Decapsulate given ciphertext/encapsulated_data and finding the shared secret using the secret_key
int kyber_decapsulate(uint8_t* encapsulated_data, uint8_t* shared_secret, uint8_t* kyber_secret_key) {
#ifndef OQS_ENABLE_KEM_kyber_768 // if Kyber-768 was not enabled at compile-time
    printf("[kyber_decapsulate] OQS_KEM_kyber_768 was not enabled at "
        "compile-time.\n");
    return FALSE; // nothing done successfully ;-)
#else
    OQS_STATUS rc = OQS_KEM_kyber_768_decaps(shared_secret, encapsulated_data, kyber_secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
        OQS_MEM_cleanse(kyber_secret_key, OQS_KEM_kyber_768_length_secret_key);
        OQS_MEM_cleanse(shared_secret, OQS_KEM_kyber_768_length_shared_secret);
        return FALSE;
    }
    return TRUE;
#endif
}

#pragma endregion

#pragma region Dilithium Functions

// Generate Dilithium key pair
int generate_dilithium_keys(uint8_t* dilithium_secret_key, uint8_t* dilithium_public_key) {
    OQS_STATUS rc = OQS_SIG_dilithium_2_keypair(dilithium_public_key, dilithium_secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
        OQS_MEM_cleanse(dilithium_secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return FALSE;
    }
    return TRUE;
}

// Sign message using Dilithium 
int dilithium_sign(uint8_t* dilithium_secret_key, uint8_t* message_to_sign, size_t message_len, uint8_t* signature, size_t* signature_len) {
    OQS_STATUS rc = OQS_SIG_dilithium_2_sign(signature, signature_len, message_to_sign, message_len, dilithium_secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
        OQS_MEM_cleanse(dilithium_secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return FALSE;
    }
    return TRUE;
}

// Verify message using Dilithium 
int dilithium_verify(uint8_t* dilithium_public_key, uint8_t* message_to_verify, size_t message_len, uint8_t* signature, size_t signature_len) {
    OQS_STATUS rc = OQS_SIG_dilithium_2_verify(message_to_verify, message_len, signature, signature_len, dilithium_public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
        return FALSE;
    }
    return TRUE;
}

#pragma endregion

void xor(const unsigned char* first, const unsigned char* second, unsigned char* result, size_t size) {
    for (size_t i = 0; i < size; i++) {
        result[i] = first[i] ^ second[i];
    }
}

int write_key_file(const char* filename, const void* data, size_t size) {
    // Open the file in binary write mode
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        return FALSE;
    }

    // Write the binary data to the file
    size_t written = fwrite(data, 1, size, file);
    if (written != size) {
        perror("Error writing to file");
        fclose(file);
        return FALSE;
    }

    // Close the file
    if (fclose(file) != 0) {
        perror("Error closing file");
        return FALSE;
    }

    return TRUE; // Success
}