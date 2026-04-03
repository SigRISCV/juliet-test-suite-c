#ifndef CWE761_SIGRISCV_CONNECT_SOCKET_HELPERS_H
#define CWE761_SIGRISCV_CONNECT_SOCKET_HELPERS_H

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32")
#define CLOSE_SOCKET closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif
#ifndef CLOSE_SOCKET
#define CLOSE_SOCKET close
#endif
#ifndef SOCKET
#define SOCKET int
#endif
#endif

#ifndef TCP_PORT
#define TCP_PORT 27015
#endif

#ifndef IP_ADDRESS
#define IP_ADDRESS "127.0.0.1"
#endif

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_fixed_string_helpers.h"

static inline void
CWE761_sigriscv_char_connect_socket_source(char *data)
{
#ifdef _WIN32
    WSADATA wsaData;
    int wsaDataInit = 0;
#endif
    int recvResult;
    struct sockaddr_in service;
    char *replace;
    SOCKET connectSocket = INVALID_SOCKET;
    size_t dataLen = strlen(data);

    do
    {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
        {
            break;
        }
        wsaDataInit = 1;
#endif
        connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connectSocket == INVALID_SOCKET)
        {
            break;
        }
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
        service.sin_port = htons(TCP_PORT);
        if (connect(connectSocket, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR)
        {
            break;
        }
        recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0);
        if (recvResult == SOCKET_ERROR || recvResult == 0)
        {
            break;
        }
        data[dataLen + recvResult / sizeof(char)] = '\0';
        replace = strchr(data, '\r');
        if (replace != NULL)
        {
            *replace = '\0';
        }
        replace = strchr(data, '\n');
        if (replace != NULL)
        {
            *replace = '\0';
        }
    }
    while (0);

    if (connectSocket != INVALID_SOCKET)
    {
        CLOSE_SOCKET(connectSocket);
    }
#ifdef _WIN32
    if (wsaDataInit)
    {
        WSACleanup();
    }
#endif

    /*
     * Preserve the socket-read structure, then normalize the local buffer so
     * SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    strcpy(data, CWE761_SIGRISCV_CHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_wchar_connect_socket_source(wchar_t *data)
{
#ifdef _WIN32
    WSADATA wsaData;
    int wsaDataInit = 0;
#endif
    int recvResult;
    struct sockaddr_in service;
    wchar_t *replace;
    SOCKET connectSocket = INVALID_SOCKET;
    size_t dataLen = wcslen(data);

    do
    {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
        {
            break;
        }
        wsaDataInit = 1;
#endif
        connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (connectSocket == INVALID_SOCKET)
        {
            break;
        }
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
        service.sin_port = htons(TCP_PORT);
        if (connect(connectSocket, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR)
        {
            break;
        }
        recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0);
        if (recvResult == SOCKET_ERROR || recvResult == 0)
        {
            break;
        }
        data[dataLen + recvResult / sizeof(wchar_t)] = L'\0';
        replace = wcschr(data, L'\r');
        if (replace != NULL)
        {
            *replace = L'\0';
        }
        replace = wcschr(data, L'\n');
        if (replace != NULL)
        {
            *replace = L'\0';
        }
    }
    while (0);

    if (connectSocket != INVALID_SOCKET)
    {
        CLOSE_SOCKET(connectSocket);
    }
#ifdef _WIN32
    if (wsaDataInit)
    {
        WSACleanup();
    }
#endif

    /*
     * Preserve the socket-read structure, then normalize the local buffer so
     * SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    wcscpy(data, CWE761_SIGRISCV_WCHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_char_connect_socket_bad_sink(char *data)
{
    CWE761_sigriscv_char_fixed_bad_sink(data);
}

static inline void
CWE761_sigriscv_wchar_connect_socket_bad_sink(wchar_t *data)
{
    CWE761_sigriscv_wchar_fixed_bad_sink(data);
}

#endif
