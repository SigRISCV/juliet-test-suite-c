#ifndef CWE761_SIGRISCV_LISTEN_SOCKET_HELPERS_H
#define CWE761_SIGRISCV_LISTEN_SOCKET_HELPERS_H

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
#include <sys/select.h>
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

#ifndef LISTEN_BACKLOG
#define LISTEN_BACKLOG 5
#endif

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_fixed_string_helpers.h"

static inline void
CWE761_sigriscv_char_listen_socket_source(char *data)
{
#ifdef _WIN32
    WSADATA wsaData;
    int wsaDataInit = 0;
#endif
    struct sockaddr_in service;
    SOCKET listenSocket = INVALID_SOCKET;
    int optval = 1;

    do
    {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
        {
            break;
        }
        wsaDataInit = 1;
#endif
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET)
        {
            break;
        }
        (void)setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(optval));
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(TCP_PORT);
        if (bind(listenSocket, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR)
        {
            break;
        }
        if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR)
        {
            break;
        }
    }
    while (0);

    if (listenSocket != INVALID_SOCKET)
    {
        CLOSE_SOCKET(listenSocket);
    }
#ifdef _WIN32
    if (wsaDataInit)
    {
        WSACleanup();
    }
#endif

    strcpy(data, CWE761_SIGRISCV_CHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_wchar_listen_socket_source(wchar_t *data)
{
#ifdef _WIN32
    WSADATA wsaData;
    int wsaDataInit = 0;
#endif
    struct sockaddr_in service;
    SOCKET listenSocket = INVALID_SOCKET;
    int optval = 1;

    do
    {
#ifdef _WIN32
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
        {
            break;
        }
        wsaDataInit = 1;
#endif
        listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET)
        {
            break;
        }
        (void)setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(optval));
        memset(&service, 0, sizeof(service));
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = INADDR_ANY;
        service.sin_port = htons(TCP_PORT);
        if (bind(listenSocket, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR)
        {
            break;
        }
        if (listen(listenSocket, LISTEN_BACKLOG) == SOCKET_ERROR)
        {
            break;
        }
    }
    while (0);

    if (listenSocket != INVALID_SOCKET)
    {
        CLOSE_SOCKET(listenSocket);
    }
#ifdef _WIN32
    if (wsaDataInit)
    {
        WSACleanup();
    }
#endif

    wcscpy(data, CWE761_SIGRISCV_WCHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_char_listen_socket_bad_sink(char *data)
{
    CWE761_sigriscv_char_fixed_bad_sink(data);
}

static inline void
CWE761_sigriscv_wchar_listen_socket_bad_sink(wchar_t *data)
{
    CWE761_sigriscv_wchar_fixed_bad_sink(data);
}

#endif
