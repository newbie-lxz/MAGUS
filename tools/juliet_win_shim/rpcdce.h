#ifndef MAGUS_JULIET_WIN_SHIM_RPCDCE_H
#define MAGUS_JULIET_WIN_SHIM_RPCDCE_H

#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UUID {
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
} UUID;

typedef unsigned char *RPC_CSTR;
typedef wchar_t *RPC_WSTR;
typedef int RPC_STATUS;

#define RPC_S_OK 0

RPC_STATUS UuidCreate(UUID *Uuid);
RPC_STATUS UuidToStringA(const UUID *Uuid, RPC_CSTR *StringUuid);
RPC_STATUS UuidToStringW(const UUID *Uuid, RPC_WSTR *StringUuid);
RPC_STATUS RpcStringFreeA(RPC_CSTR *String);
RPC_STATUS RpcStringFreeW(RPC_WSTR *String);

#ifdef UNICODE
#define UuidToString UuidToStringW
#define RpcStringFree RpcStringFreeW
#else
#define UuidToString UuidToStringA
#define RpcStringFree RpcStringFreeA
#endif

#ifdef __cplusplus
}
#endif

#endif
