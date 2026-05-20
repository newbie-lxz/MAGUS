#ifndef MAGUS_JULIET_WIN_SHIM_WINDOWS_H
#define MAGUS_JULIET_WIN_SHIM_WINDOWS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int BOOL;
typedef unsigned long DWORD;
typedef void *HANDLE;
typedef const char *LPCSTR;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef WINAPI
#define WINAPI
#endif

#ifndef INFINITE
#define INFINITE 0xffffffffUL
#endif

#define WAIT_OBJECT_0 0

BOOL WINAPI SetComputerNameA(LPCSTR lpComputerName);
DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
BOOL WINAPI CloseHandle(HANDLE hObject);

typedef struct _CRITICAL_SECTION {
    void *DebugInfo;
    long LockCount;
    long RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    unsigned long SpinCount;
} CRITICAL_SECTION;

void WINAPI InitializeCriticalSection(CRITICAL_SECTION *lpCriticalSection);
void WINAPI EnterCriticalSection(CRITICAL_SECTION *lpCriticalSection);
void WINAPI LeaveCriticalSection(CRITICAL_SECTION *lpCriticalSection);
void WINAPI DeleteCriticalSection(CRITICAL_SECTION *lpCriticalSection);

#ifdef __cplusplus
}
#endif

#endif
