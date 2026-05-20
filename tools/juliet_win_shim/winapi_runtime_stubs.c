#include "winsock2.h"
#include "windows.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *payload_value(void)
{
    const char *payload = getenv("MAGUS_CWE15_PAYLOAD");
    if (payload == NULL || payload[0] == '\0')
    {
        return "magus-cwe15-controlled-host";
    }
    return payload;
}

int globalReturnsTrueOrFalse(void)
{
    return 1;
}

int WSAStartup(WORD wVersionRequired, WSADATA *lpWSAData)
{
    (void)wVersionRequired;
    if (lpWSAData != NULL)
    {
        memset(lpWSAData, 0, sizeof(*lpWSAData));
    }
    return NO_ERROR;
}

int WSACleanup(void)
{
    return 0;
}

SOCKET socket(int af, int type, int protocol)
{
    (void)af;
    (void)type;
    (void)protocol;
    return (SOCKET)1;
}

int bind(SOCKET s, const struct sockaddr *name, int namelen)
{
    (void)s;
    (void)name;
    (void)namelen;
    return 0;
}

int listen(SOCKET s, int backlog)
{
    (void)s;
    (void)backlog;
    return 0;
}

SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen)
{
    (void)s;
    (void)addr;
    (void)addrlen;
    return (SOCKET)2;
}

int recv(SOCKET s, char *buf, int len, int flags)
{
    const char *payload = payload_value();
    size_t payload_len;
    size_t copy_len;

    (void)s;
    (void)flags;

    if (buf == NULL || len <= 0)
    {
        return SOCKET_ERROR;
    }

    payload_len = strlen(payload);
    copy_len = payload_len < (size_t)len ? payload_len : (size_t)len;
    memcpy(buf, payload, copy_len);
    return (int)copy_len;
}

int closesocket(SOCKET s)
{
    (void)s;
    return 0;
}

unsigned short htons(unsigned short hostshort)
{
    return (unsigned short)((hostshort << 8) | (hostshort >> 8));
}

BOOL WINAPI SetComputerNameA(LPCSTR lpComputerName)
{
    const char *payload = payload_value();
    const char *name = lpComputerName == NULL ? "" : lpComputerName;

    printf("MAGUS_CWE15_SET_COMPUTER_NAME value=%s\n", name);
    if (strcmp(name, payload) == 0)
    {
        printf("MAGUS_CWE15_CONFIRMED external payload reached SetComputerNameA\n");
    }
    return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    (void)hHandle;
    (void)dwMilliseconds;
    return WAIT_OBJECT_0;
}

BOOL WINAPI CloseHandle(HANDLE hObject)
{
    (void)hObject;
    return TRUE;
}

void WINAPI InitializeCriticalSection(CRITICAL_SECTION *lpCriticalSection)
{
    if (lpCriticalSection != NULL)
    {
        memset(lpCriticalSection, 0, sizeof(*lpCriticalSection));
    }
}

void WINAPI EnterCriticalSection(CRITICAL_SECTION *lpCriticalSection)
{
    (void)lpCriticalSection;
}

void WINAPI LeaveCriticalSection(CRITICAL_SECTION *lpCriticalSection)
{
    (void)lpCriticalSection;
}

void WINAPI DeleteCriticalSection(CRITICAL_SECTION *lpCriticalSection)
{
    (void)lpCriticalSection;
}
