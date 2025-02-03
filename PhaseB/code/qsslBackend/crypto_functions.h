#pragma once
#include "params.h"


#pragma region To Delete
typedef BOOL(*VerifyECCSignature)(EC_KEY* verify_key, unsigned char* message, size_t message_len, unsigned char* signature, unsigned int sig_len);

typedef BOOL(*SignECCSignature)(EC_KEY* sign_key, unsigned char* message, size_t message_len, unsigned char* signature, unsigned int* sig_len);

typedef BOOL(*RSAEncrypt)(RSA* rsa_enc_key, unsigned char* message, size_t message_len, unsigned char* ciphertext, size_t* ciphertext_len);

typedef BOOL(*RSADecrypt)(RSA* rsa_dec_key, unsigned char* ciphertext, size_t cipher_len, unsigned char* plaintext, size_t* plaintext_len);

typedef BOOL(*AESEncrypt)(unsigned char* enc_key, unsigned char* plaintext, size_t plaintext_len, unsigned char* iv,
    unsigned char* ciphertext, size_t* cipher_len);

typedef BOOL(*AESDecrypt)(unsigned char* dec_key, unsigned char* ciphertext, size_t cipher_len, unsigned char* iv,
    unsigned char* plaintext, size_t* plaintext_len);

#pragma endregion

#pragma region ECC Functions

BOOL ecc_verify(EC_KEY* verify_key, unsigned char* message, size_t message_len, unsigned char* signature, unsigned int sig_len);

BOOL ecc_sign(EC_KEY* sign_key, unsigned char* message, size_t message_len, unsigned char* signature, unsigned int* sig_len);

char* serialize_ecc_key(EC_KEY* ecc_public_key, size_t* key_len);

EC_KEY* deserialize_ecc_key(const char* key_data, size_t key_len);

int generate_ecc_keys(EC_KEY** ecc_private_key, EC_KEY** ecc_public_key);

#pragma endregion

#pragma region RSA Functions

BOOL rsa_encrypt(RSA* rsa_enc_key, unsigned char* message, size_t message_len, unsigned char* ciphertext, size_t* ciphertext_len);

BOOL rsa_decrypt(RSA* rsa_dec_key, unsigned char* ciphertext, size_t cipher_len, unsigned char* plaintext, size_t* plaintext_len);

char* serialize_rsa_key(RSA* rsa_public_key, size_t* key_len);

RSA* deserialize_rsa_key(const char* key_data, size_t key_len);

int generate_rsa_keys(RSA** rsa_private_key, RSA** rsa_public_key);

#pragma endregion

#pragma region AES Functions

BOOL aes_encrypt(unsigned char* enc_key, unsigned char* plaintext, size_t plaintext_len, unsigned char* iv,
    unsigned char* ciphertext, size_t* cipher_len);

BOOL aes_decrypt(unsigned char* dec_key, unsigned char* ciphertext, size_t cipher_len, unsigned char* iv,
    unsigned char* plaintext, size_t* plaintext_len);

int generate_aes_key(unsigned char* key,int key_len);

#pragma endregion


#pragma region Kyber Functions

int generate_kyber_keys(uint8_t* kyber_secret_key, uint8_t* kyber_public_key);

int kyber_encapsulate(uint8_t* encapsulated_data, uint8_t* shared_secret, uint8_t* kyber_public_key);

int kyber_decapsulate(uint8_t* encapsulated_data, uint8_t* shared_secret, uint8_t* kyber_secret_key);

#pragma endregion

#pragma region Dilithium Functions

int generate_dilithium_keys(uint8_t* dilithium_secret_key, uint8_t* dilithium_public_key);

int dilithium_sign(uint8_t* dilithium_secret_key, uint8_t* message_to_sign, size_t message_len, uint8_t* signature, size_t* signature_len);

int dilithium_verify(uint8_t* dilithium_public_key, uint8_t* message_to_verify, size_t message_len, uint8_t* signature, size_t signature_len);

#pragma endregion

void xor(const unsigned char* first, const unsigned char* second, unsigned char* result, size_t size);

int write_key_file(const char* filename, const void* data, size_t size);