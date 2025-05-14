#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#define SOCK5_CLIENT_ERR_OK               0
#define SOCK5_CLIENT_ERR_SOCKET_INIT_FAIL -1
#define SOCK5_CLIENT_ERR_CONNECT_FAIL     -2
#define SOCK5_CLIENT_ERR_GREETING_FAIL    -3
#define SOCK5_CLIENT_ERR_AUTH_FAIL        -4
#define SOCK5_CLIENT_ERR_CONNECT_DST_FAIL -5

typedef struct {
    SOCKET fd;
    int    err_code;
} SOCK5Client;

typedef struct {
    unsigned char auth;
    char          *username;
    char          *password;
} SOCK5Auth;

SOCK5Client *new_sock5_client(const char *host, int port);
void sock5_client_free(SOCK5Client *client);
int sock5_client_connect(SOCK5Client *client, const char *dst_host, int dst_port, SOCK5Auth *auth);