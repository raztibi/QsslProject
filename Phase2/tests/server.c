#include "server.h"

void server_cleanup(Server* server)
{
    if (!server) return;

    if (server->rsa_private_key) {
        RSA_free(server->rsa_private_key);
        server->rsa_private_key = NULL;
    }

    if (server->rsa_public_key) {
        RSA_free(server->rsa_public_key);
        server->rsa_public_key = NULL;
    }

    if (server->ecc_private_key) {
        EC_KEY_free(server->ecc_private_key);
        server->ecc_private_key = NULL;
    }

    if (server->ecc_public_key) {
        EC_KEY_free(server->ecc_public_key);
        server->ecc_public_key = NULL;
    }

    if (server->kyber_private_key) {
        OQS_MEM_cleanse(server->kyber_private_key, OQS_KEM_kyber_768_length_secret_key);
    }

    if (server->kyber_shared_secret) {
        OQS_MEM_cleanse(server->kyber_shared_secret, OQS_KEM_kyber_768_length_shared_secret);
    }

    if (server->dilithium_private_key) {
        OQS_MEM_cleanse(server->dilithium_private_key, OQS_SIG_dilithium_2_length_secret_key);
    }

    server->is_initialized = FALSE;
    EVP_cleanup();
    ERR_free_strings();
}

int server_init(Server* server) 
{
    if (!server) {
        return FALSE;
    }
    if (server->is_initialized == TRUE)
    {
        return TRUE;
    }

    int rc = generate_rsa_keys(&server->rsa_private_key, &server->rsa_public_key);
    if (rc != TRUE)
    {
        printf("rsa keys generation failed!");
        server_cleanup(server);
        return FALSE;
    }

    rc = generate_ecc_keys(&server->ecc_private_key, &server->ecc_public_key);
    if (rc != TRUE)
    {
        printf("ecc keys generation failed!");
        server_cleanup(server);
        return FALSE;
    }
   
    rc = generate_kyber_keys(&server->kyber_private_key, &server->kyber_public_key);
    if (rc != TRUE)
    {
        printf("kyber keys generation failed!");
        server_cleanup(server);
        return FALSE;
    } 

    rc = generate_dilithium_keys(&server->dilithium_private_key, &server->dilithium_public_key);
    if (rc != TRUE)
    {
        printf("dilithium keys generation failed!");
        server_cleanup(server);
        return FALSE;
    }

    // Initialize function pointers
    server->cleanup = server_cleanup;

    server->is_initialized = TRUE;
    return TRUE;
}

int public_key_exchange_server(Server* server,Client_Keys* cl_keys, int server_fd, struct sockaddr_in client_addr)
{
    size_t key_len;
    char* serialized_key = NULL;

    // Serialize RSA public key
    serialized_key = serialize_rsa_key(server->rsa_public_key, &key_len);
    if (!serialized_key) {
        RSA_free(server->rsa_public_key);
        RSA_free(server->rsa_private_key);
        printf("failed to serilaze rsa key!\n");
        return FALSE;
    }
    // Send the RSA Key
    char* message_to_send = "RSA Key";
    send_and_receive(server_fd, client_addr, message_to_send,strlen(message_to_send));
    send_and_receive(server_fd, client_addr, serialized_key, key_len);

    // Serialize ECC public key
    serialized_key = serialize_ecc_key(server->ecc_public_key, &key_len);
    if (!serialized_key) {
        EC_KEY_free(server->ecc_public_key);
        printf("failed to serilaze ecc key!\n");
        return FALSE;
    }
    // Send the ECC Key
    message_to_send = "ECC Key";
    send_and_receive(server_fd, client_addr, message_to_send, strlen(message_to_send));
    send_and_receive(server_fd, client_addr, serialized_key, key_len);

    // Send the Kyber Key
    message_to_send = "Kyber Key";
    send_and_receive(server_fd, client_addr, message_to_send, strlen(message_to_send));
    send_and_receive(server_fd, client_addr, server->kyber_public_key, OQS_KEM_kyber_768_length_secret_key);

    // Send the Dilithium Key
    message_to_send = "Dilithium Key";
    send_and_receive(server_fd, client_addr, message_to_send, strlen(message_to_send));
    send_and_receive(server_fd, client_addr, server->dilithium_public_key, OQS_SIG_dilithium_2_length_public_key);

    printf("all public keys sent successfully\n");
    
    // Recieve the ECC Key
    char* client_message = NULL;
    print_header_and_free(server_fd, client_addr, &client_message, &key_len);
    receive_and_send(server_fd, client_addr, &client_message, &key_len);
    if (client_message) {
        cl_keys->ecc_public_key = deserialize_ecc_key(client_message, key_len);
        if (cl_keys->ecc_public_key) {
            printf("ECC public key successfully deserialized!\n");
        }
        else {
            fprintf(stderr, "Failed to deserialize ECC public key\n");
            return FALSE;
        }
    }

    // Recieve the Dilithium Key
    client_message = NULL;
    print_header_and_free(server_fd, client_addr, &client_message, &key_len);
    receive_and_send(server_fd, client_addr, &client_message, &key_len);
    
    if (key_len == OQS_SIG_dilithium_2_length_public_key) {
        // saving the key in the cl_keys struct
        memcpy(cl_keys->dilithium_public_key, client_message, key_len);
        printf("Dilithium public key successfully saved!\n");
    }
    else {
        fprintf(stderr, "Failed to save Dilithium public key\n");
        return FALSE;
    }

    printf("client public keys saved successfully\n");
    return TRUE;
}

int handshake_server(Server* server, Client_Keys* cl_keys, int server_fd, struct sockaddr_in client_addr, unsigned char* session_key)
{
    int rc , errCode = 0;
    unsigned int ecc_signature_len = 0;
    unsigned char* encrypted_key = NULL, *signature = NULL;
    unsigned char  decrypted_key[AES_KEY_SIZE];
    uint8_t* encapsulated_message = NULL, shared_secret[OQS_KEM_kyber_768_length_shared_secret];
    size_t encrypted_len = 0, message_len = 0, decrypted_len = 0, encapsulated_len = 0, dil_sign_len = 0, ecc_sign_len_size_t = 0;

    // Recieve the AES Key with RSA encryption
    char* client_message = NULL;
    print_header_and_free(server_fd, client_addr, &client_message, &message_len);
    receive_and_send(server_fd, client_addr, &encrypted_key, &encrypted_len);
    if (!encrypted_key) 
    {
            fprintf(stderr, "Failed to get encrypted key from client\n");
    }
    // Recieve the ECC Signature
    client_message = NULL;
    print_header_and_free(server_fd, client_addr, &client_message, &message_len);
    receive_and_send(server_fd, client_addr, &signature, &ecc_sign_len_size_t);
    if (!signature)
    {
        fprintf(stderr, "Failed to get encrypted key signature from client\n");
    }

    ecc_signature_len = (unsigned int)ecc_sign_len_size_t;
    // Verify ECC signature
    rc = ecc_verify(cl_keys->ecc_public_key, encrypted_key, encrypted_len, signature, ecc_signature_len);
    if (rc != TRUE) {
        printf("failed to verify the message using ECC!\n");
        errCode = -1;
    }
    else {// if we fail to verify there is no need to decrypt the message
        rc = rsa_decrypt(server->rsa_private_key, encrypted_key, encrypted_len, decrypted_key, &decrypted_len);
        if (rc != TRUE) {
            printf("failed to decrypt RSA !\n");
            errCode = -2;
        }
    }


    // Recieve the Kyber shared secret
    client_message = NULL;
    print_header_and_free(server_fd, client_addr, &client_message, &message_len);
    receive_and_send(server_fd, client_addr, &encapsulated_message, &encapsulated_len);
    if (!encapsulated_message)
    {
        fprintf(stderr, "Failed to get encapsulated message from client\n");
    }
    // Recieve the Dilithium Signature
    client_message = NULL;
    print_header_and_free(server_fd, client_addr, &client_message, &message_len);
    receive_and_send(server_fd, client_addr, &signature, &dil_sign_len);
    if (!signature)
    {
        fprintf(stderr, "Failed to get encapsulated message signature from client\n");
    }

    // Verify Dilithium signature
    rc = dilithium_verify(cl_keys->dilithium_public_key, encapsulated_message, encapsulated_len, signature, dil_sign_len);
    if (rc != TRUE) {
        printf("failed to verify the message using Dilithium!\n");
        errCode = -3;
    }
    else {// if we fail to verify there is no need to decapsulate the message
        rc = kyber_decapsulate(encapsulated_message, shared_secret,server->kyber_private_key);
        if (rc != TRUE) {
            printf("failed to decpasulate Kyber !\n");
            errCode = -4;
        }
    }

    if (errCode < 0)
    {
        printf("transfer of session key failed with error code - %d", errCode);
        return TRUE;
    }

    printf("transfer of session key completed\n");
    // create the session key using xor between both keys
    xor (decrypted_key, shared_secret, session_key, AES_KEY_SIZE);
    printf("Session key is Ready to use\n");

    return TRUE;
}

int recv_encrypted_user(int server_fd, struct sockaddr_in client_addr, unsigned char* enc_key, uint8_t* dilithium_client_public_key, 
                        uint8_t* dilithium_server_private_key, unsigned char* result, size_t* res_len)
{
    unsigned char iv[AES_BLOCK_SIZE] = "000000000000000";
    unsigned char plaintext[256], dil_sign[OQS_SIG_dilithium_2_length_signature];
    unsigned char* messageToSend = NULL;
    size_t plain_len = 0, dil_sign_len = 0, sent_len = 0;
    memset(plaintext, '\0', 256);

    // waiting for message from client
    unsigned char buffer[BUFFER_SIZE];
    size_t recv_len = recvfrom(server_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
        perror("recvfrom - recv_encrypted_user");
        return;
    }

    int encryptMessageSize = recv_len - OQS_SIG_dilithium_2_length_signature;

    // verify the message
    int rc = dilithium_verify(dilithium_client_public_key, buffer, encryptMessageSize, buffer + encryptMessageSize, OQS_SIG_dilithium_2_length_signature);
    if (rc != TRUE)
    {
        printf("Failed to Verify the message! - recv_encrypted_user\n");
        return FALSE;
    }
   
    // decrypt the data
    rc = aes_decrypt(enc_key, buffer, encryptMessageSize, iv, result, res_len);
    if (rc != TRUE)
    {
        printf("Failed to Decrypt the message! - recv_encrypted_user\n");
        return FALSE;
    }

    return TRUE;
}

int send_encrypted_answer(int server_fd, struct sockaddr_in client_addr, unsigned char* enc_key,
    uint8_t* dilithium_server_private_key, const unsigned char* message, size_t msg_len)
{
    unsigned char iv[AES_BLOCK_SIZE] = "000000000000000";
    unsigned char ciphertext[256], dil_sign[OQS_SIG_dilithium_2_length_signature];
    unsigned char* messageToSend = NULL;
    size_t cipher_len = 0, dil_sign_len = 0, sent_len = 0;

    memset(ciphertext, '\0', 256);
    int rc = aes_encrypt(enc_key, message, msg_len, iv, ciphertext, &cipher_len);
    if (rc != TRUE)
    {
        printf("Failed to encrypt the message! - send_encrypted_answer\n");
        return FALSE;
    }

    rc = dilithium_sign(dilithium_server_private_key, ciphertext, cipher_len, dil_sign, &dil_sign_len);
    if (rc != TRUE)
    {
        printf("Failed to Sign the message! - send_encrypted_answer\n");
        return FALSE;
    }


    sent_len = cipher_len + dil_sign_len;
    messageToSend = malloc(sent_len);
    if (messageToSend == NULL) {
        perror("malloc - send_encrypted_answer");
        return FALSE;
    }

    // copy encrypted message and signature
    memcpy(messageToSend, ciphertext, cipher_len);
    memcpy((messageToSend + cipher_len), dil_sign, dil_sign_len);
    (messageToSend)[sent_len] = '\0';

    int sendto_len = sendto(server_fd, messageToSend, sent_len, 0, (const struct sockaddr*)&client_addr, sizeof(client_addr));
    if (sendto_len < 0) {
        perror("sendto - send_encrypted_answer");
        return FALSE;
    }
    else if ((size_t)sendto_len != sent_len) {
        fprintf(stderr, "Incomplete key sent: %zd/%zu bytes - send_encrypted_answer\n", sendto_len, sent_len);
        return FALSE;
    }

    return TRUE;
}

int parse_user_and_check_validity(const char* message,size_t len)
{
    // Parse the message
    unsigned short usernameLen = *(unsigned short*)message;
    // check length
    if (usernameLen != strlen("admin"))
        return FALSE;
    
    char username[256] = { 0 };
    memcpy(username, message + 2, usernameLen);
    username[usernameLen] = '\0';

    unsigned short passwordLen = *(unsigned short*)(message + 2 + usernameLen);
    // check length
    if (passwordLen != strlen("password"))
        return FALSE;

    char password[256] = { 0 };
    memcpy(password, message + 2 + usernameLen + 2, passwordLen);
    password[passwordLen] = '\0';
    
    // check data
    if(memcmp(username, "admin", usernameLen) != 0 || memcmp(password, "password", passwordLen) != 0)
        return FALSE;

    return TRUE;
}

int main() {
    WSADATA wsaData;
    int server_fd, rc;
    struct sockaddr_in server_addr, client_addr;
    unsigned char buffer[BUFFER_SIZE], session_key[AES_KEY_SIZE];
    socklen_t client_addr_len = sizeof(client_addr);
    Client_Keys ck;
    Server server;
    rc = server_init(&server);
    if (rc != TRUE)
    {
        printf("server init failed!, exiting...");
        return;
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (const struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server is running on port %d\n", SERVER_PORT);

    // Receive Hello message from client
    memset(buffer, 0, BUFFER_SIZE);
    int n = recvfrom(server_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_addr_len);
    if (n < 0) {
        perror("Receive failed");
        return;
    }

    buffer[n] = '\0';
    printf("Client: %s\n", buffer);

    // start tls handshake
    rc = public_key_exchange_server(&server,&ck, server_fd, client_addr);
    if (rc != TRUE)
    {
        printf("tls_server failed!, exiting...");
        return;
    }

    // Receive the session key
    rc = handshake_server(&server, &ck, server_fd, client_addr, session_key);
    if (rc != TRUE)
    {
        printf("handshake_server failed!, exiting...");
        return;
    }


    rc = write_key_file("shared_server.bin", session_key, AES_KEY_SIZE);
    if (rc != TRUE)
    {
        printf("failed to write to file, exiting...");
        return;
    }


    size_t buff_len = 0;
    unsigned char answer[5];
    // loop for safe communication
    while (1)
    {
        memset(buffer, '\0', 256);
        memset(answer, '\0', 5);
        rc = recv_encrypted_user(server_fd, client_addr, session_key, ck.dilithium_public_key,
            server.dilithium_private_key, buffer, &buff_len);
        if (rc != TRUE)
        {
            printf("failed to get encrypted user, exiting...\n");
            break;
        }

        printf("Got encrypted message from Client\n");

        rc = parse_user_and_check_validity(buffer, buff_len);
        if (rc == TRUE) {
            memcpy(answer, "Good", 4); 
            answer[4] = '\0'; 
        }
        else {
            memcpy(answer, "Bad", 3);
            answer[3] = '\0'; 
        }

        rc = send_encrypted_answer(server_fd,client_addr,session_key,server.dilithium_private_key, answer,strlen(answer));
        if (rc != TRUE)
        {
            printf("failed to send encrypted answer, exiting...\n");
            break;
        }

        printf("Sent encrypted %s to Client\n", answer);
    }

    // Cleanup
    server.cleanup(&server);
    closesocket(server_fd);
    WSACleanup();
    system("PAUSE");
    return 0;
}