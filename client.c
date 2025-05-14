#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#include "include/sock5/client.h"

const char AUTH_METHOD_NONE              = 0x00;
const char AUTH_METHOD_USERNAME_PASSWORD = 0x02;

const char ADDRESS_TYPE_IPV4   = 0x01;
const char ADDRESS_TYPE_DOMAIN = 0x03;
const char ADDRESS_TYPE_IPV6   = 0x04;

const char COMMAND_CONNECT  = 0x01;
const char COMMAND_BIND     = 0x02;
const char COMMAND_UDPASSOC = 0x03;

const char CONN_REPLY_SUCCEEDED                  = 0x00;
const char CONN_REPLY_GENERAL_FAILURE            = 0x01;
const char CONN_REPLY_NOT_ALLOWED                = 0x02;
const char CONN_REPLY_NETWORK_UNREACHABLE        = 0x03;
const char CONN_REPLY_HOST_UNREACHABLE           = 0x04;
const char CONN_REPLY_CONNECTION_REFUSED         = 0x05;
const char CONN_REPLY_TTL_EXPIRED                = 0x06;
const char CONN_REPLY_COMMAND_NOT_SUPPORTED      = 0x07;
const char CONN_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

SOCK5Client *new_sock5_client(const char *host, int port)
{
    struct WSAData     wsa_data;
    struct sockaddr_in addr = { 0 };

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return NULL;
    }

    SOCK5Client *client = (SOCK5Client *)malloc(sizeof(SOCK5Client));

    client->err_code = SOCK5_CLIENT_ERR_OK;
    client->fd       = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (client->fd == INVALID_SOCKET) {
        client->err_code = SOCK5_CLIENT_ERR_SOCKET_INIT_FAIL;
        return client;
    }

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);

    if (connect(client->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        client->err_code = SOCK5_CLIENT_ERR_CONNECT_FAIL;
        return client;
    }

    return client;
}

void sock5_client_free(SOCK5Client *client)
{
    if (client == NULL) return;
    if (client->fd != INVALID_SOCKET) closesocket(client->fd);

    WSACleanup();

    free(client);
}

int sock5_client_connect(SOCK5Client *client, const char *dst_host, int dst_port, SOCK5Auth *auth)
{
    char phase          = 0;
    char data_send[513] = { 0 };
    char data_recv[262] = { 0 };

    while (1)
    {
        switch (phase)
        {
            case 0: // greeting
            {
                data_send[0] = 0x05;                          // version
                data_send[1] = 2;                             // auth method size
                data_send[2] = AUTH_METHOD_NONE;              // method 1
                data_send[3] = AUTH_METHOD_USERNAME_PASSWORD; // method 2

                if (send(client->fd, data_send, 4, 0) < 0) {
                    client->err_code = SOCK5_CLIENT_ERR_GREETING_FAIL;
                    return 0;
                }

                if (recv(client->fd, data_recv, 2, 0) < 0) {
                    client->err_code = SOCK5_CLIENT_ERR_GREETING_FAIL;
                    return 0;
                }

                if (data_recv[0] != 0x05) {
                    client->err_code = SOCK5_CLIENT_ERR_GREETING_FAIL;
                    return 0;
                }

                if (data_recv[1] == AUTH_METHOD_NONE) {
                    phase = 2;
                    break;
                }

                if (data_recv[1] == AUTH_METHOD_USERNAME_PASSWORD)
                {
                    phase = 1;
                    break;
                }

                client->err_code = SOCK5_CLIENT_ERR_GREETING_FAIL;
                return 0;
            }

            case 1: // auth
            {
                if (auth == NULL || auth->username == NULL || auth->password == NULL) {
                    client->err_code = SOCK5_CLIENT_ERR_AUTH_FAIL;
                    return 0;
                }

                char id_len = (char)strlen(auth->username);
                char pw_len = (char)strlen(auth->password);

                data_send[0]          = 0x05;
                data_send[1]          = id_len;
                data_send[2 + id_len] = pw_len;
                memcpy(data_send + 2,          auth->username, id_len);
                memcpy(data_send + 3 + id_len, auth->password, pw_len);

                if (send(client->fd, data_send, 3 + id_len + pw_len, 0) < 0) {
                    client->err_code = SOCK5_CLIENT_ERR_AUTH_FAIL;
                    return 0;
                }

                if (recv(client->fd, data_recv, 2, 0) < 0) {
                    client->err_code = SOCK5_CLIENT_ERR_AUTH_FAIL;
                    return 0;
                }

                if (data_recv[0] != 0x05 || data_recv[1] != 0x00) {
                    client->err_code = SOCK5_CLIENT_ERR_AUTH_FAIL;
                    return 0;
                }

                phase = 2;
                break;
            }

            case 2: // connect
            {
                size_t next_read_sz = 0;
                char   dst_host_len = (char)strlen(dst_host);

                data_send[0]                = 0x05;                   // version
                data_send[1]                = COMMAND_CONNECT;        // command
                data_send[2]                = 0x00;                   // reserved
                data_send[3]                = ADDRESS_TYPE_DOMAIN;    // address type
                data_send[4]                = dst_host_len;           // address length
                data_send[5 + dst_host_len] = (dst_port >> 8) & 0xFF; // port h
                data_send[6 + dst_host_len] = (dst_port)      & 0xFF; // port l
                memcpy(data_send + 5, dst_host, dst_host_len);        // address

                if (send(client->fd, data_send, 7 + dst_host_len, 0) < 0) {
                    client->err_code = SOCK5_CLIENT_ERR_CONNECT_DST_FAIL;
                    return 0;
                }

                if (recv(client->fd, data_recv, 5, 0) < 0) {
                    client->err_code = SOCK5_CLIENT_ERR_CONNECT_DST_FAIL;
                    return 0;
                }

                if (data_recv[0] != 0x05) {
                    client->err_code = SOCK5_CLIENT_ERR_CONNECT_DST_FAIL;
                    return 0;
                }

                if (data_recv[1] != CONN_REPLY_SUCCEEDED) {
                    client->err_code = SOCK5_CLIENT_ERR_CONNECT_DST_FAIL;
                    return 0;
                }

                if (data_recv[3] == ADDRESS_TYPE_IPV4) {
                    next_read_sz = 5;
                } else if (data_recv[3] == ADDRESS_TYPE_DOMAIN) {
                    next_read_sz = 2 + data_recv[4];
                }

                if (next_read_sz == 0) {
                    client->err_code = SOCK5_CLIENT_ERR_CONNECT_DST_FAIL;
                    return 0;
                }

                if (recv(client->fd, data_recv + 5, next_read_sz, 0) < 0) {
                    client->err_code = SOCK5_CLIENT_ERR_CONNECT_DST_FAIL;
                    return 0;
                }

                client->err_code = SOCK5_CLIENT_ERR_OK;
                return 1;
            }
        }
    }
}
