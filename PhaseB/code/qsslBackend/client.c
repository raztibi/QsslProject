#include "client.h"

void client_cleanup(Client* client)
{
    if (!client) return;

    if (client->ecc_private_key) {
        EC_KEY_free(client->ecc_private_key);
        client->ecc_private_key = NULL;
    }

    if (client->ecc_public_key) {
        EC_KEY_free(client->ecc_public_key);
        client->ecc_public_key = NULL;
    }

    if (client->dilithium_private_key) {
        OQS_MEM_cleanse(client->dilithium_private_key, OQS_SIG_dilithium_2_length_secret_key);
    }

    client->is_initialized = FALSE;

    SAFE_AES_KEY_MEMSET(client->aes_key);
    EVP_cleanup();
    ERR_free_strings();
}

int client_init(Client* client)
{
    if (!client) {
        return FALSE;
    }
    if (client->is_initialized == TRUE)
    {
        return TRUE;
    }

    int rc = generate_aes_key(client->aes_key, AES_KEY_SIZE);
    if (rc != TRUE)
    {
        printf("aes keys generation failed!");
        client_cleanup(client);
        return FALSE;
    }
    
    rc = generate_ecc_keys(&client->ecc_private_key, &client->ecc_public_key);
    if (rc != TRUE)
    {
        printf("ecc keys generation failed!");
        client_cleanup(client);
        return FALSE;
    }

    rc = generate_dilithium_keys(&client->dilithium_private_key, &client->dilithium_public_key);
    if (rc != TRUE)
    {
        printf("dilithium keys generation failed!");
        client_cleanup(client);
        return FALSE;
    }

    // Initialize function pointers
    client->cleanup = client_cleanup;

    client->is_initialized = TRUE;
    return TRUE;
}

int public_key_exchange_client(Client* client, Server_Keys* ser_keys, int client_fd, struct sockaddr_in server_addr)
{
    size_t key_len = 0;
    char* server_message = NULL;
    
    // Recieve the RSA Key
    print_header_and_free(client_fd, server_addr, &server_message, &key_len);
    receive_and_send(client_fd, server_addr, &server_message, &key_len);
    if (server_message) {
        // Deserialize the public key
        ser_keys->rsa_public_key = deserialize_rsa_key(server_message, key_len);
        if (ser_keys->rsa_public_key) {
            printf("RSA public key successfully deserialized!\n");
        }
        else {
            fprintf(stderr, "Failed to deserialize RSA public key\n");
            return FALSE;
        }
    }

    // Recieve the ECC Key
    print_header_and_free(client_fd, server_addr, &server_message, &key_len);
    receive_and_send(client_fd, server_addr, &server_message, &key_len);
    if (server_message) {
        ser_keys->ecc_public_key = deserialize_ecc_key(server_message, key_len);
        if (ser_keys->ecc_public_key) {
            printf("ECC public key successfully deserialized!\n");
        }
        else {
            fprintf(stderr, "Failed to deserialize ECC public key\n");
            return FALSE;
        }
    }
    
    // Recieve the Kyber Key
    print_header_and_free(client_fd, server_addr, &server_message, &key_len);
    receive_and_send(client_fd, server_addr, &server_message, &key_len);
    if (key_len == OQS_KEM_kyber_768_length_secret_key) {
        // saving the key in the cl_keys struct
        memcpy(ser_keys->kyber_public_key, server_message, key_len);
        printf("Kyber public key successfully saved!\n");
    }
    else {
        fprintf(stderr, "Failed to save Kyber public key\n");
        return FALSE;
    }

    // Recieve the Dilithium Key
    print_header_and_free(client_fd, server_addr, &server_message, &key_len);
    receive_and_send(client_fd, server_addr, &server_message, &key_len);
    if (key_len == OQS_SIG_dilithium_2_length_public_key) {
        // saving the key in the cl_keys struct
        memcpy(ser_keys->dilithium_public_key, server_message, key_len);
        printf("Dilithium public key successfully saved!\n");
    }
    else {
        fprintf(stderr, "Failed to save Dilithium public key\n");
        return FALSE;
    }

    printf("server public keys saved successfully\n");

    char* serialized_key = NULL;
   
    // Serialize ECC public key
    serialized_key = serialize_ecc_key(client->ecc_public_key, &key_len);
    if (!serialized_key) {
        EC_KEY_free(client->ecc_public_key);
        printf("failed to serilaze ecc key!\n");
        return FALSE;
    }
    // Send the ECC Key
    char* message_to_send = "ECC Key";
    send_and_receive(client_fd, server_addr, message_to_send, strlen(message_to_send));
    send_and_receive(client_fd, server_addr, serialized_key, key_len);

    // Send the Dilithium Key
    message_to_send = "Dilithium Key";
    send_and_receive(client_fd, server_addr, message_to_send, strlen(message_to_send));
    send_and_receive(client_fd, server_addr, client->dilithium_public_key, OQS_SIG_dilithium_2_length_public_key);

    printf("all public keys sent successfully\n");
    return TRUE;
}

int handshake_client(Client* client, Server_Keys* ser_keys,const int client_fd, struct sockaddr_in server_addr, unsigned char* session_key)
{
    int rc;
    unsigned int ecc_signature_len = 0;
    size_t encrypted_len = 0, dil_sign_len = 0;
    char* message_to_send = NULL;
    unsigned char encrypted_key[RSA_KEY_SIZE / 8], ecc_sig[64], dil_sign[OQS_SIG_dilithium_2_length_signature];
    uint8_t encapsulated_message[OQS_KEM_kyber_768_length_ciphertext], shared_secret[OQS_KEM_kyber_768_length_shared_secret];  

    // Encrypt AES key using RSA
    rc = rsa_encrypt(ser_keys->rsa_public_key, client->aes_key, AES_KEY_SIZE, encrypted_key, &encrypted_len);
    if (rc != TRUE) {
        printf("failed to encrypt aes key!\n");
        return FALSE;
    }

    // Sign the Key using ECC
    rc = ecc_sign(client->ecc_private_key, encrypted_key, encrypted_len, ecc_sig, &ecc_signature_len);
    if (rc != TRUE) {
        printf("failed to sign the key using ECC!\n");
        return FALSE;
    }

    // Send the Encrypted Key
    message_to_send = "Encrypted AES Key";
    send_and_receive(client_fd, server_addr, message_to_send, strlen(message_to_send));
    send_and_receive(client_fd, server_addr, encrypted_key, encrypted_len);
    // Send the Encrypted Key Signature
    message_to_send = "Signature for AES Key";
    send_and_receive(client_fd, server_addr, message_to_send, strlen(message_to_send));
    send_and_receive(client_fd, server_addr, ecc_sig, ecc_signature_len);

    // Encapsulate data using Kyber
    rc = kyber_encapsulate(encapsulated_message, shared_secret, ser_keys->kyber_public_key);
    if (rc != TRUE) {
        printf("failed to encapsulate with kyber!\n");
        return FALSE;
    }

    // Sign the Key using Dilithium
    rc = dilithium_sign(client->dilithium_private_key, encapsulated_message, OQS_KEM_kyber_768_length_ciphertext, dil_sign, &dil_sign_len);
    if (rc != TRUE) {
        printf("failed to sign the key using Dilithium!\n");
        return FALSE;
    }

    // Send the Encapsulated message
    message_to_send = "Encapsulated Kyber Data";
    send_and_receive(client_fd, server_addr, message_to_send, strlen(message_to_send));
    send_and_receive(client_fd, server_addr, encapsulated_message, OQS_KEM_kyber_768_length_ciphertext);
    // Send the Dilithium Signature
    message_to_send = "Dilithium Signature";
    send_and_receive(client_fd, server_addr, message_to_send, strlen(message_to_send));
    send_and_receive(client_fd, server_addr, dil_sign, dil_sign_len);

    printf("transfer of session key completed\n");

    // create the session key using xor between both keys
    xor(client->aes_key,shared_secret,session_key,AES_KEY_SIZE);
    printf("Session key is Ready to use\n");

    return TRUE;
}

int read_binary_file(const unsigned char* filename, unsigned char** dest, size_t* size) {
    
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return FALSE;
    }

    // Move to the end of the file to determine its size
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("Error seeking file");
        fclose(file);
        return FALSE;
    }

    long file_size = ftell(file);
    if (file_size < 0) {
        perror("Error getting file size");
        fclose(file);
        return FALSE;
    }

    // Return to the start of the file
    rewind(file);

    // Allocate memory for the buffer
    *dest = (unsigned char*)malloc(file_size);
    if (!*dest) {
        perror("Error allocating memory");
        fclose(file);
        return FALSE;
    }

    // Read the file into the buffer
    size_t read_size = fread(*dest, 1, file_size, file);
    if (read_size != (size_t)file_size) {
        perror("Error reading file");
        free(*dest);
        fclose(file);
        return FALSE;
    }

    // Set the size and close the file
    *size = read_size;
    fclose(file);
    return TRUE;
}

int send_user_with_encrypt_sign_and_result(int server_fd, struct sockaddr_in client_addr, const unsigned char* message, size_t len,
                                unsigned char* enc_key, uint8_t* dilithium_client_secret_key, uint8_t* dilithium_server_public_key, unsigned char* result, size_t*  res_len)
{
    unsigned char iv[AES_BLOCK_SIZE] = "000000000000000";
    unsigned char ciphertext[256], dil_sign[OQS_SIG_dilithium_2_length_signature];
    unsigned char* messageToSend = NULL;
    size_t cipher_len = 0, dil_sign_len = 0,sent_len=0;
    memset(ciphertext,'\0', 256);

    //write_key_file("usernamecheck.bin", message,len);

    int rc = aes_encrypt(enc_key, message,len,iv,ciphertext,&cipher_len);
    if (rc != TRUE)
    {
        printf("Failed to encrypt the message!\n");
        return FALSE;
    }

    //write_key_file("usernamecheckEcnrypted.bin", ciphertext, cipher_len);

    rc = dilithium_sign(dilithium_client_secret_key, ciphertext, cipher_len, dil_sign,&dil_sign_len);
    if (rc != TRUE)
    {
        printf("Failed to Sign the message!\n");
        return FALSE;
    }


    sent_len = cipher_len + dil_sign_len;
    messageToSend = malloc(sent_len);
    if (messageToSend == NULL) {
        perror("malloc - aes_encrypt_send_and_recv");
        return FALSE;
    }

    // copy encrypted message and signature
    memcpy(messageToSend, ciphertext, cipher_len);
    memcpy((messageToSend + cipher_len), dil_sign, dil_sign_len);
    (messageToSend)[sent_len] = '\0';

    int sendto_len = sendto(server_fd, messageToSend, sent_len, 0, (const struct sockaddr*)&client_addr, sizeof(client_addr));
    if (sent_len < 0) {
        perror("sendto - aes_encrypt_send_and_recv");
        return FALSE;
    }
    else if ((size_t)sendto_len != sent_len) {
        fprintf(stderr, "Incomplete key sent: %zd/%zu bytes - aes_encrypt_send_and_recv\n", len, sent_len);
        return FALSE;
    }

    printf("Sent encrypted message to Server!\n");

    // waiting for response from server
    unsigned char buffer[BUFFER_SIZE];
    size_t recv_len = recvfrom(server_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (recv_len < 0) {
        perror("recvfrom - send_user_with_encrypt_sign_and_result");
        return FALSE;
    }
    
    int encryptMessageSize = recv_len - OQS_SIG_dilithium_2_length_signature;

   rc = dilithium_verify(dilithium_server_public_key, buffer, encryptMessageSize, buffer + encryptMessageSize, OQS_SIG_dilithium_2_length_signature);
   if (rc != TRUE)
   {
       printf("Failed to Verify the message!\n");
       return FALSE;
   }

   unsigned char iv2[AES_BLOCK_SIZE] = "000000000000000";
   rc = aes_decrypt(enc_key, buffer, encryptMessageSize, iv2, result, res_len);
   if (rc != TRUE)
   {
       printf("Failed to Decrypt the message!\n");
       return FALSE;
   }
   result[*res_len] = "\0";

   printf("Got encrypted message from Server!\n");

   return TRUE;
}

int main() {
    WSADATA wsaData;
    int client_fd, rc,wpf_fd, isUser = 0, isPath = 0;
    struct sockaddr_in server_addr,wpf_client_addr,wpf_server_addr;
    unsigned char buffer[BUFFER_SIZE], session_key[AES_KEY_SIZE],resultofDecryption[256];
    unsigned char* wpfBuffer = NULL, *sessionKeyToUse = NULL;
    size_t wpf_message_len=0, keyLenFromFile=0,resultOfDecryption_len=0;
    socklen_t wpf__client_addr_len = sizeof(wpf_client_addr);
    Server_Keys sk;
    Client client;

    rc = client_init(&client);
    if (rc != TRUE)
    {
        printf("client init failed!, exiting...");
        return;
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return EXIT_FAILURE;
    }

    // Create socket
    if ((client_fd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return EXIT_FAILURE;
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(LOCALHOST);

    // Send message to server
    const char* message = "Hello, Server!";
    sendto(client_fd, message, strlen(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    // Transfer public keys between client and server
    rc = public_key_exchange_client(&client, &sk, client_fd, server_addr);
    if (rc != TRUE)
    {
        printf("public_key_exchange_client failed!, exiting...");
        return;
    }

    // Create the session key and send it
    rc = handshake_client(&client, &sk, client_fd, server_addr, session_key);
    if (rc != TRUE)
    {
        printf("handshake_client failed!, exiting...");
        return;
    }

    // Write key to PC
    rc = write_key_file("shared_client.bin", session_key, AES_KEY_SIZE);
    if (rc != TRUE)
    {
        printf("failed to write to file, exiting...");
        return;
    }

    //Setting up communication with WPF
    // Create socket
    if ((wpf_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the address
    memset(&wpf_server_addr, 0, sizeof(server_addr));
    wpf_server_addr.sin_family = AF_INET;
    wpf_server_addr.sin_addr.s_addr = INADDR_ANY;
    wpf_server_addr.sin_port = htons(WPF_CLIENT_PORT);

    if (bind(wpf_fd, (const struct sockaddr*)&wpf_server_addr, sizeof(wpf_server_addr)) < 0) {
        perror("Bind WPF failed");
        close(wpf_fd);
        exit(EXIT_FAILURE);
    }

    printf("WPF receiver is running on port %d\n", WPF_CLIENT_PORT);

    // Receive Hello message from client WPF
    memset(buffer, 0, BUFFER_SIZE);
    int n = recvfrom(wpf_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&wpf_client_addr, &wpf__client_addr_len);
    if (n < 0) {
        perror("Receive hello WPF failed");
        return;
    }
    printf("Got Hello message from WPF receiver: %s \n", buffer);

    // loop for safe communication
    while (1)
    {
        memset(resultofDecryption, '\0', 256);
        
        // Receive message from WPF
        receive_and_send(wpf_fd, wpf_client_addr, &wpfBuffer, &wpf_message_len);
        
        // Check if the message is "Path"
        if (wpf_message_len == 4 && memcmp(wpfBuffer, "Path", 4) == 0) {
            printf("Got 'Path' Message from WPF.\n");
            isPath = 1;
        }
        // Check if the message is "User"
        else if (wpf_message_len == 4 && memcmp(wpfBuffer, "User", 4) == 0) {
            printf("Got 'User' Message from WPF.\n");
            isUser = 1;
        }
        else {
            continue;
        }
        receive_and_send(wpf_fd, wpf_client_addr, &wpfBuffer, &wpf_message_len);
        if (isPath == 1)
        {
            rc = read_binary_file(wpfBuffer, &sessionKeyToUse, &keyLenFromFile);
            if (rc != TRUE)
            {
                perror("Read File WPF failed");
                break;
            }
            isPath = 0;
        }
        else if (isUser == 1)
        {
            rc = send_user_with_encrypt_sign_and_result(client_fd, server_addr, wpfBuffer, wpf_message_len, sessionKeyToUse,
                    client.dilithium_private_key, sk.dilithium_public_key, resultofDecryption, &resultOfDecryption_len);
            if (rc != TRUE)
            {
                perror("Send User to server failed, return False to WPF!");

                size_t sent_len = sendto(wpf_fd, "False", sizeof("False"), 0, (const struct sockaddr*)&wpf_client_addr, sizeof(wpf_client_addr));
                if (sent_len < 0) {
                    perror("sendto wpf");
                }
                break;
            }

            // Check if the message is "Good"
            if (resultOfDecryption_len == 4 && memcmp(resultofDecryption, "Good", 4) == 0) {
                size_t sent_len = sendto(wpf_fd, "Good", strlen("Good"), 0, (const struct sockaddr*)&wpf_client_addr, sizeof(wpf_client_addr));
                if (sent_len < 0) {
                    perror("sendto wpf");
                }
                printf("Sent Good To WPF.\n");
            }
            else {
                size_t sent_len = sendto(wpf_fd, "Bad", strlen("Bad"), 0, (const struct sockaddr*)&wpf_client_addr, sizeof(wpf_client_addr));
                if (sent_len < 0) {
                    perror("sendto wpf");
                }
                printf("Sent Bad To WPF.\n");
            }
        }
    }

    // Cleanup
    client.cleanup(&client);
    closesocket(wpf_fd);
    closesocket(client_fd);
    WSACleanup();
    system("PAUSE");
    return 0;
}