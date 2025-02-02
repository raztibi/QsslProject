#pragma once
#include "params.h"

#define BUFFER_SIZE  4096
#define SERVER_PORT 8080
#define WPF_CLIENT_PORT 8081
#define LOCALHOST "127.0.0.1"

void send_and_receive(int server_fd, struct sockaddr_in client_addr, const char* message, size_t len);

void receive_and_send(int server_fd, struct sockaddr_in client_addr, const char** message, size_t* len);

void print_header_and_free(int fd, struct sockaddr_in addr, const char** message, size_t* len);