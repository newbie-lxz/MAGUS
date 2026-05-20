#ifndef MAGUS_JULIET_WIN_SHIM_WINSOCK2_H
#define MAGUS_JULIET_WIN_SHIM_WINSOCK2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int BOOL;
typedef uintptr_t SOCKET;
typedef uint16_t WORD;
typedef unsigned short u_short;

typedef struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char *lpVendorInfo;
} WSADATA;

struct in_addr {
    unsigned long s_addr;
};

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define NO_ERROR 0
#define INVALID_SOCKET ((SOCKET)(~(uintptr_t)0))
#define SOCKET_ERROR (-1)
#define AF_INET 2
#define PF_INET AF_INET
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define INADDR_ANY 0UL

#define MAKEWORD(low, high) ((WORD)((((WORD)(high)) << 8) | ((WORD)(low))))

int WSAStartup(WORD wVersionRequired, WSADATA *lpWSAData);
int WSACleanup(void);
SOCKET socket(int af, int type, int protocol);
int bind(SOCKET s, const struct sockaddr *name, int namelen);
int listen(SOCKET s, int backlog);
SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen);
int recv(SOCKET s, char *buf, int len, int flags);
int closesocket(SOCKET s);
unsigned short htons(unsigned short hostshort);

#ifdef __cplusplus
}
#endif

#endif
