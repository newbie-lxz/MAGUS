#include "winsock2.h"
#include "windows.h"
#include "Winldap.h"
#include "wincrypt.h"
#include "shlwapi.h"
#include "rpcdce.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

static uintptr_t next_handle_value = 0x1000;
static DWORD last_error_value = 0;

typedef struct _MAGUS_HANDLE_STATE {
    HANDLE handle;
    int closed;
    const char *kind;
} MAGUS_HANDLE_STATE;

static MAGUS_HANDLE_STATE handle_states[4096];
static size_t handle_state_count = 0;

typedef struct _MAGUS_KEY_STATE {
    HCRYPTKEY key;
    ALG_ID alg;
} MAGUS_KEY_STATE;

static MAGUS_KEY_STATE key_states[1024];
static size_t key_state_count = 0;

typedef struct _MAGUS_LOCK_STATE {
    const void *address;
    size_t size;
    int active;
} MAGUS_LOCK_STATE;

static MAGUS_LOCK_STATE lock_states[1024];
static size_t lock_state_count = 0;

static void register_handle(HANDLE handle, const char *kind)
{
    if (handle == NULL || handle == INVALID_HANDLE_VALUE || handle_state_count >= sizeof(handle_states) / sizeof(handle_states[0]))
    {
        return;
    }
    handle_states[handle_state_count].handle = handle;
    handle_states[handle_state_count].closed = 0;
    handle_states[handle_state_count].kind = kind;
    handle_state_count++;
}

static MAGUS_HANDLE_STATE *find_handle_state(HANDLE handle)
{
    size_t i;
    for (i = 0; i < handle_state_count; i++)
    {
        if (handle_states[i].handle == handle)
        {
            return &handle_states[i];
        }
    }
    return NULL;
}

static HANDLE fake_handle_kind(const char *kind)
{
    HANDLE handle;
    next_handle_value += 0x10;
    handle = (HANDLE)next_handle_value;
    register_handle(handle, kind);
    return handle;
}

static HANDLE fake_handle(void)
{
    return fake_handle_kind("handle");
}

static void register_key(HCRYPTKEY key, ALG_ID alg)
{
    if (key == NULL || key_state_count >= sizeof(key_states) / sizeof(key_states[0]))
    {
        return;
    }
    key_states[key_state_count].key = key;
    key_states[key_state_count].alg = alg;
    key_state_count++;
}

static ALG_ID key_alg(HCRYPTKEY key)
{
    size_t i;
    for (i = 0; i < key_state_count; i++)
    {
        if (key_states[i].key == key)
        {
            return key_states[i].alg;
        }
    }
    return 0;
}

static const char *payload_value(void)
{
    const char *payload = getenv("MAGUS_JULIET_PAYLOAD");
    if (payload == NULL || payload[0] == '\0')
    {
        payload = getenv("MAGUS_CWE15_PAYLOAD");
    }
    if (payload == NULL || payload[0] == '\0')
    {
        return "magus-juliet-controlled-input";
    }
    return payload;
}

static int contains_payload(const char *value)
{
    const char *payload = payload_value();
    if (value == NULL)
    {
        return 0;
    }
    return strstr(value, payload) != NULL;
}

static void wide_to_narrow(const wchar_t *input, char *output, size_t output_size)
{
    size_t i;
    if (output_size == 0)
    {
        return;
    }
    if (input == NULL)
    {
        output[0] = '\0';
        return;
    }
    for (i = 0; i + 1 < output_size && input[i] != L'\0'; i++)
    {
        wchar_t ch = input[i];
        output[i] = (ch >= 0 && ch < 0x80) ? (char)ch : '?';
    }
    output[i] = '\0';
}

static void sink_marker(const char *name, const char *value)
{
    printf(
        "MAGUS_JULIET_SINK name=%s tainted=%d value=%s\n",
        name,
        contains_payload(value),
        value == NULL ? "" : value);
}

static void sink_marker_w(const char *name, const wchar_t *value)
{
    char buffer[512];
    wide_to_narrow(value, buffer, sizeof(buffer));
    sink_marker(name, buffer);
}

static void flaw_marker(const char *name, const char *value, const char *reason)
{
    printf(
        "MAGUS_JULIET_FLAW name=%s reason=%s value=%s\n",
        name,
        reason == NULL ? "" : reason,
        value == NULL ? "" : value);
}

static void flaw_marker_w(const char *name, const wchar_t *value, const char *reason)
{
    char buffer[512];
    wide_to_narrow(value, buffer, sizeof(buffer));
    flaw_marker(name, buffer, reason);
}

static int is_relative_library_path(const char *value)
{
    if (value == NULL || value[0] == '\0')
    {
        return 0;
    }
    if (value[0] == '/' || value[0] == '\\')
    {
        return 0;
    }
    if (strlen(value) >= 2 && value[1] == ':')
    {
        return 0;
    }
    return 1;
}

static int is_relative_library_path_w(const wchar_t *value)
{
    char buffer[512];
    wide_to_narrow(value, buffer, sizeof(buffer));
    return is_relative_library_path(buffer);
}

static void append_narrow_arg(char *buffer, size_t buffer_size, const char *value)
{
    size_t used;
    if (buffer == NULL || buffer_size == 0 || value == NULL)
    {
        return;
    }
    used = strlen(buffer);
    if (used + 1 < buffer_size && used > 0)
    {
        strncat(buffer, " ", buffer_size - used - 1);
        used = strlen(buffer);
    }
    if (used + 1 < buffer_size)
    {
        strncat(buffer, value, buffer_size - used - 1);
    }
}

static void append_wide_arg(wchar_t *buffer, size_t buffer_size, const wchar_t *value)
{
    size_t used;
    if (buffer == NULL || buffer_size == 0 || value == NULL)
    {
        return;
    }
    used = wcslen(buffer);
    if (used + 1 < buffer_size && used > 0)
    {
        wcsncat(buffer, L" ", buffer_size - used - 1);
        used = wcslen(buffer);
    }
    if (used + 1 < buffer_size)
    {
        wcsncat(buffer, value, buffer_size - used - 1);
    }
}

static void sink_marker_argv_a(const char *name, const char *cmdname, const char *const *argv)
{
    char combined[1024] = "";
    int i;
    append_narrow_arg(combined, sizeof(combined), cmdname);
    if (argv != NULL)
    {
        for (i = 0; argv[i] != NULL && i < 32; i++)
        {
            append_narrow_arg(combined, sizeof(combined), argv[i]);
        }
    }
    sink_marker(name, combined);
}

static void sink_marker_argv_w(const char *name, const wchar_t *cmdname, const wchar_t *const *argv)
{
    wchar_t combined[1024] = L"";
    int i;
    append_wide_arg(combined, sizeof(combined) / sizeof(combined[0]), cmdname);
    if (argv != NULL)
    {
        for (i = 0; argv[i] != NULL && i < 32; i++)
        {
            append_wide_arg(combined, sizeof(combined) / sizeof(combined[0]), argv[i]);
        }
    }
    sink_marker_w(name, combined);
}

static intptr_t process_marker_varargs_a(const char *name, const char *cmdname, const char *arg0, va_list ap)
{
    char combined[1024] = "";
    const char *arg = arg0;
    int count = 0;
    append_narrow_arg(combined, sizeof(combined), cmdname);
    while (arg != NULL && count < 32)
    {
        append_narrow_arg(combined, sizeof(combined), arg);
        arg = va_arg(ap, const char *);
        count++;
    }
    sink_marker(name, combined);
    return 0;
}

static intptr_t process_marker_varargs_w(const char *name, const wchar_t *cmdname, const wchar_t *arg0, va_list ap)
{
    wchar_t combined[1024] = L"";
    const wchar_t *arg = arg0;
    int count = 0;
    append_wide_arg(combined, sizeof(combined) / sizeof(combined[0]), cmdname);
    while (arg != NULL && count < 32)
    {
        append_wide_arg(combined, sizeof(combined) / sizeof(combined[0]), arg);
        arg = va_arg(ap, const wchar_t *);
        count++;
    }
    sink_marker_w(name, combined);
    return 0;
}

static void copy_string(char *dest, size_t dest_size, const char *value)
{
    if (dest == NULL || dest_size == 0)
    {
        return;
    }
    snprintf(dest, dest_size, "%s", value == NULL ? "" : value);
}

static void copy_wstring(wchar_t *dest, size_t dest_size, const wchar_t *value)
{
    if (dest == NULL || dest_size == 0)
    {
        return;
    }
    wcsncpy(dest, value == NULL ? L"" : value, dest_size - 1);
    dest[dest_size - 1] = L'\0';
}

static char *narrow_from_wide_alloc(const wchar_t *value)
{
    size_t len;
    char *result;
    if (value == NULL)
    {
        return NULL;
    }
    len = wcslen(value);
    result = (char *)malloc(len + 1);
    if (result == NULL)
    {
        return NULL;
    }
    wide_to_narrow(value, result, len + 1);
    return result;
}

static wchar_t *wide_from_narrow_static(const char *value)
{
    static wchar_t buffer[512];
    size_t i;
    if (value == NULL)
    {
        buffer[0] = L'\0';
        return buffer;
    }
    for (i = 0; i + 1 < sizeof(buffer) / sizeof(buffer[0]) && value[i] != '\0'; i++)
    {
        buffer[i] = (unsigned char)value[i];
    }
    buffer[i] = L'\0';
    return buffer;
}

static wchar_t *wide_strdup_alloc(const wchar_t *value)
{
    size_t len;
    wchar_t *result;
    if (value == NULL)
    {
        return NULL;
    }
    len = wcslen(value);
    result = (wchar_t *)malloc((len + 1) * sizeof(wchar_t));
    if (result == NULL)
    {
        return NULL;
    }
    copy_wstring(result, len + 1, value);
    return result;
}

static int replace_x_suffix(char *template_name, size_t size)
{
    size_t len;
    size_t first_x;
    size_t i;
    if (template_name == NULL || size == 0)
    {
        return EINVAL;
    }
    for (len = 0; len < size && template_name[len] != '\0'; len++)
    {
    }
    if (len == size)
    {
        return EINVAL;
    }
    first_x = len;
    while (first_x > 0 && template_name[first_x - 1] == 'X')
    {
        first_x--;
    }
    if (first_x == len)
    {
        return EINVAL;
    }
    for (i = first_x; i < len; i++)
    {
        template_name[i] = (char)('A' + ((i - first_x) % 26));
    }
    return 0;
}

static int replace_wx_suffix(wchar_t *template_name)
{
    size_t len;
    size_t first_x;
    size_t i;
    if (template_name == NULL)
    {
        return EINVAL;
    }
    len = wcslen(template_name);
    first_x = len;
    while (first_x > 0 && template_name[first_x - 1] == L'X')
    {
        first_x--;
    }
    if (first_x == len)
    {
        return EINVAL;
    }
    for (i = first_x; i < len; i++)
    {
        template_name[i] = (wchar_t)(L'A' + ((i - first_x) % 26));
    }
    return 0;
}

static intptr_t process_marker_a(const char *name, const char *cmdname)
{
    sink_marker(name, cmdname);
    return 0;
}

static intptr_t process_marker_w(const char *name, const wchar_t *cmdname)
{
    sink_marker_w(name, cmdname);
    return 0;
}

static int env_enabled(const char *name)
{
    const char *value = getenv(name);
    return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}

static int pointer_is_locked(const void *address)
{
    size_t i;
    const char *ptr = (const char *)address;
    for (i = 0; i < lock_state_count; i++)
    {
        const char *start;
        const char *end;
        if (!lock_states[i].active)
        {
            continue;
        }
        start = (const char *)lock_states[i].address;
        end = start + lock_states[i].size;
        if (ptr >= start && ptr < end)
        {
            return 1;
        }
    }
    return 0;
}

static void report_handle_leaks(void)
{
    size_t i;
    if (!env_enabled("MAGUS_JULIET_REPORT_HANDLE_LEAKS"))
    {
        return;
    }
    for (i = 0; i < handle_state_count; i++)
    {
        if (!handle_states[i].closed && handle_states[i].kind != NULL && strcmp(handle_states[i].kind, "CreateFile") == 0)
        {
            flaw_marker("CreateFile", "", "missing_closehandle");
        }
    }
}

__attribute__((constructor)) static void register_process_reporters(void)
{
    atexit(report_handle_leaks);
}

int rand(void)
{
    static unsigned value = 1;
    value = value * 1103515245U + 12345U;
    if (env_enabled("MAGUS_JULIET_MARK_RAND_FLAW"))
    {
        flaw_marker("rand", "", "cryptographically_weak_prng");
    }
    return (int)((value / 65536U) % 32768U);
}

void srand(unsigned seed)
{
    (void)seed;
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

int connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    (void)s;
    (void)name;
    (void)namelen;
    return 0;
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
    struct sockaddr_in *in_addr_value;
    (void)s;
    if (addr != NULL)
    {
        memset(addr, 0, sizeof(struct sockaddr_in));
        in_addr_value = (struct sockaddr_in *)addr;
        in_addr_value->sin_family = AF_INET;
        in_addr_value->sin_addr.s_addr = inet_addr("127.0.0.1");
        if (addrlen != NULL)
        {
            *addrlen = (int)sizeof(struct sockaddr_in);
        }
    }
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

    if (env_enabled("MAGUS_JULIET_SOCKET_WIDE"))
    {
        wchar_t *wide_buf = (wchar_t *)buf;
        size_t max_chars = (size_t)len / sizeof(wchar_t);
        size_t i;
        if (max_chars == 0)
        {
            return SOCKET_ERROR;
        }
        payload_len = strlen(payload);
        copy_len = payload_len < max_chars ? payload_len : max_chars;
        for (i = 0; i < copy_len; i++)
        {
            wide_buf[i] = (wchar_t)(unsigned char)payload[i];
        }
        return (int)(copy_len * sizeof(wchar_t));
    }

    payload_len = strlen(payload);
    copy_len = payload_len < (size_t)len ? payload_len : (size_t)len;
    memcpy(buf, payload, copy_len);
    return (int)copy_len;
}

int send(SOCKET s, const char *buf, int len, int flags)
{
    (void)s;
    (void)flags;
    sink_marker("send", buf);
    return len;
}

int shutdown(SOCKET s, int how)
{
    (void)s;
    (void)how;
    return 0;
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

unsigned long inet_addr(const char *cp)
{
    (void)cp;
    return 0x0100007fUL;
}

struct hostent *gethostbyaddr(const char *addr, int len, int type)
{
    static char hostname[] = "www.domain.nonexistanttld";
    static char *aliases[] = {NULL};
    static char addr_bytes[4] = {127, 0, 0, 1};
    static char *addr_list[] = {addr_bytes, NULL};
    static struct hostent host;
    (void)addr;
    (void)len;
    host.h_name = hostname;
    host.h_aliases = aliases;
    host.h_addrtype = (short)type;
    host.h_length = 4;
    host.h_addr_list = addr_list;
    flaw_marker("gethostbyaddr", hostname, "reverse_dns_used_for_security_decision");
    return &host;
}

BOOL WINAPI SetComputerNameA(LPCSTR lpComputerName)
{
    sink_marker("SetComputerNameA", lpComputerName);
    if (contains_payload(lpComputerName))
    {
        printf("MAGUS_CWE15_CONFIRMED external payload reached SetComputerNameA\n");
    }
    return TRUE;
}

BOOL WINAPI SetComputerNameW(LPCWSTR lpComputerName)
{
    sink_marker_w("SetComputerNameW", lpComputerName);
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
    MAGUS_HANDLE_STATE *state;
    if (hObject == NULL || hObject == INVALID_HANDLE_VALUE)
    {
        flaw_marker("CloseHandle", "", "invalid_or_failed_handle_used");
        return FALSE;
    }
    state = find_handle_state(hObject);
    if (state != NULL)
    {
        if (state->closed)
        {
            flaw_marker("CloseHandle", "", "duplicate_close");
            return FALSE;
        }
        state->closed = 1;
    }
    else
    {
        flaw_marker("CloseHandle", "", "unrecognized_handle_or_wrong_close_api");
        return FALSE;
    }
    return TRUE;
}

DWORD WINAPI GetLastError(void)
{
    return last_error_value;
}

HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName)
{
    sink_marker("LoadLibraryA", lpLibFileName);
    if (is_relative_library_path(lpLibFileName))
    {
        flaw_marker("LoadLibraryA", lpLibFileName, "relative_library_path");
    }
    return fake_handle();
}

HMODULE WINAPI LoadLibraryW(LPCWSTR lpLibFileName)
{
    sink_marker_w("LoadLibraryW", lpLibFileName);
    if (is_relative_library_path_w(lpLibFileName))
    {
        flaw_marker_w("LoadLibraryW", lpLibFileName, "relative_library_path");
    }
    return fake_handle();
}

BOOL WINAPI FreeLibrary(HMODULE hLibModule)
{
    (void)hLibModule;
    sink_marker("FreeLibrary", "");
    return TRUE;
}

FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    (void)hModule;
    sink_marker("GetProcAddress", lpProcName);
    return 1;
}

HANDLE WINAPI CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    (void)dwDesiredAccess;
    (void)dwShareMode;
    (void)lpSecurityAttributes;
    (void)dwCreationDisposition;
    (void)dwFlagsAndAttributes;
    (void)hTemplateFile;
    sink_marker("CreateFileA", lpFileName);
    return fake_handle_kind("CreateFile");
}

HANDLE WINAPI CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    (void)dwDesiredAccess;
    (void)dwShareMode;
    (void)lpSecurityAttributes;
    (void)dwCreationDisposition;
    (void)dwFlagsAndAttributes;
    (void)hTemplateFile;
    sink_marker_w("CreateFileW", lpFileName);
    return fake_handle_kind("CreateFile");
}

HANDLE WINAPI CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName)
{
    (void)lpMutexAttributes;
    (void)bInitialOwner;
    sink_marker("CreateMutexA", lpName);
    if (env_enabled("MAGUS_JULIET_FAIL_CREATE_MUTEX"))
    {
        last_error_value = STATUS_NO_MEMORY;
        flaw_marker("CreateMutexA", lpName, "forced_null_return_for_return_value_check");
        return NULL;
    }
    return fake_handle();
}

HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)
{
    (void)lpMutexAttributes;
    (void)bInitialOwner;
    sink_marker_w("CreateMutexW", lpName);
    if (env_enabled("MAGUS_JULIET_FAIL_CREATE_MUTEX"))
    {
        last_error_value = STATUS_NO_MEMORY;
        flaw_marker_w("CreateMutexW", lpName, "forced_null_return_for_return_value_check");
        return NULL;
    }
    return fake_handle();
}

HANDLE WINAPI CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    (void)dwOpenMode;
    (void)dwPipeMode;
    (void)nMaxInstances;
    (void)nOutBufferSize;
    (void)nInBufferSize;
    (void)nDefaultTimeOut;
    (void)lpSecurityAttributes;
    sink_marker("CreateNamedPipeA", lpName);
    if (env_enabled("MAGUS_JULIET_FAIL_CREATE_NAMED_PIPE"))
    {
        last_error_value = STATUS_NO_MEMORY;
        flaw_marker("CreateNamedPipeA", lpName, "forced_invalid_handle_for_return_value_check");
        return INVALID_HANDLE_VALUE;
    }
    return fake_handle();
}

HANDLE WINAPI CreateNamedPipeW(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    (void)dwOpenMode;
    (void)dwPipeMode;
    (void)nMaxInstances;
    (void)nOutBufferSize;
    (void)nInBufferSize;
    (void)nDefaultTimeOut;
    (void)lpSecurityAttributes;
    sink_marker_w("CreateNamedPipeW", lpName);
    if (env_enabled("MAGUS_JULIET_FAIL_CREATE_NAMED_PIPE"))
    {
        last_error_value = STATUS_NO_MEMORY;
        flaw_marker_w("CreateNamedPipeW", lpName, "forced_invalid_handle_for_return_value_check");
        return INVALID_HANDLE_VALUE;
    }
    return fake_handle();
}

BOOL WINAPI ConnectNamedPipe(HANDLE hNamedPipe, LPVOID lpOverlapped)
{
    (void)lpOverlapped;
    sink_marker("ConnectNamedPipe", "");
    if (hNamedPipe == NULL || hNamedPipe == INVALID_HANDLE_VALUE)
    {
        last_error_value = STATUS_NO_MEMORY;
        flaw_marker("ConnectNamedPipe", "", "invalid_or_failed_handle_used");
        return FALSE;
    }
    return TRUE;
}

static void fill_process_info(LPPROCESS_INFORMATION lpProcessInformation)
{
    if (lpProcessInformation != NULL)
    {
        lpProcessInformation->hProcess = fake_handle();
        lpProcessInformation->hThread = fake_handle();
        lpProcessInformation->dwProcessId = 1001;
        lpProcessInformation->dwThreadId = 1002;
    }
}

BOOL WINAPI CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    (void)lpProcessAttributes;
    (void)lpThreadAttributes;
    (void)bInheritHandles;
    (void)dwCreationFlags;
    (void)lpEnvironment;
    (void)lpCurrentDirectory;
    (void)lpStartupInfo;
    sink_marker("CreateProcessA", lpCommandLine != NULL ? lpCommandLine : lpApplicationName);
    fill_process_info(lpProcessInformation);
    return TRUE;
}

BOOL WINAPI CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    (void)lpProcessAttributes;
    (void)lpThreadAttributes;
    (void)bInheritHandles;
    (void)dwCreationFlags;
    (void)lpEnvironment;
    (void)lpCurrentDirectory;
    (void)lpStartupInfo;
    sink_marker_w("CreateProcessW", lpCommandLine != NULL ? lpCommandLine : lpApplicationName);
    fill_process_info(lpProcessInformation);
    return TRUE;
}

BOOL WINAPI CreateProcessAsUserA(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    (void)hToken;
    return CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    (void)hToken;
    return CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL WINAPI LogonUserA(LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, HANDLE *phToken)
{
    (void)lpszUsername;
    (void)lpszDomain;
    (void)dwLogonType;
    (void)dwLogonProvider;
    sink_marker("LogonUserA", lpszPassword);
    if (!pointer_is_locked(lpszPassword))
    {
        flaw_marker("LogonUserA", lpszPassword, "sensitive_password_not_virtually_locked");
    }
    if (phToken != NULL)
    {
        *phToken = fake_handle();
    }
    return TRUE;
}

BOOL WINAPI LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, HANDLE *phToken)
{
    (void)lpszUsername;
    (void)lpszDomain;
    (void)dwLogonType;
    (void)dwLogonProvider;
    sink_marker_w("LogonUserW", lpszPassword);
    if (!pointer_is_locked(lpszPassword))
    {
        flaw_marker_w("LogonUserW", lpszPassword, "sensitive_password_not_virtually_locked");
    }
    if (phToken != NULL)
    {
        *phToken = fake_handle();
    }
    return TRUE;
}

BOOL WINAPI ImpersonateNamedPipeClient(HANDLE hNamedPipe)
{
    (void)hNamedPipe;
    sink_marker("ImpersonateNamedPipeClient", "");
    if (env_enabled("MAGUS_JULIET_FAIL_IMPERSONATE_NAMED_PIPE_CLIENT"))
    {
        last_error_value = STATUS_NO_MEMORY;
        flaw_marker("ImpersonateNamedPipeClient", "", "forced_false_return_for_privilege_drop_check");
        return FALSE;
    }
    return TRUE;
}

BOOL WINAPI RevertToSelf(void)
{
    sink_marker("RevertToSelf", "");
    return TRUE;
}

BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE *TokenHandle)
{
    (void)ProcessHandle;
    (void)DesiredAccess;
    if (TokenHandle != NULL)
    {
        *TokenHandle = fake_handle();
    }
    return TRUE;
}

BOOL WINAPI DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel, int TokenType, HANDLE *phNewToken)
{
    (void)hExistingToken;
    (void)dwDesiredAccess;
    (void)lpTokenAttributes;
    (void)ImpersonationLevel;
    (void)TokenType;
    if (phNewToken != NULL)
    {
        *phNewToken = fake_handle();
    }
    return TRUE;
}

BOOL WINAPI VirtualLock(LPVOID lpAddress, size_t dwSize)
{
    if (lock_state_count < sizeof(lock_states) / sizeof(lock_states[0]))
    {
        lock_states[lock_state_count].address = lpAddress;
        lock_states[lock_state_count].size = dwSize;
        lock_states[lock_state_count].active = 1;
        lock_state_count++;
    }
    sink_marker("VirtualLock", "");
    return TRUE;
}

BOOL WINAPI VirtualUnlock(LPVOID lpAddress, size_t dwSize)
{
    size_t i;
    (void)dwSize;
    for (i = 0; i < lock_state_count; i++)
    {
        if (lock_states[i].address == lpAddress)
        {
            lock_states[i].active = 0;
        }
    }
    sink_marker("VirtualUnlock", "");
    return TRUE;
}

DWORD WINAPI GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer)
{
    const char *path = ".";
    if (lpBuffer != NULL && nBufferLength > 0)
    {
        copy_string(lpBuffer, nBufferLength, path);
    }
    return (DWORD)strlen(path);
}

DWORD WINAPI GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer)
{
    const wchar_t *path = L".";
    if (lpBuffer != NULL && nBufferLength > 0)
    {
        copy_wstring(lpBuffer, nBufferLength, path);
    }
    return (DWORD)wcslen(path);
}

UINT WINAPI GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName)
{
    char value[256];
    snprintf(value, sizeof(value), "%s/%s%u.tmp", lpPathName ? lpPathName : ".", lpPrefixString ? lpPrefixString : "tmp", uUnique ? uUnique : 1);
    copy_string(lpTempFileName, MAX_PATH, value);
    sink_marker("GetTempFileNameA", value);
    if (uUnique == 0)
    {
        flaw_marker("GetTempFileNameA", value, "uUnique_zero_creates_then_closes_file");
    }
    return uUnique ? uUnique : 1;
}

UINT WINAPI GetTempFileNameW(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName)
{
    wchar_t value[256];
    swprintf(value, sizeof(value) / sizeof(value[0]), L"%ls/%ls%u.tmp", lpPathName ? lpPathName : L".", lpPrefixString ? lpPrefixString : L"tmp", uUnique ? uUnique : 1);
    copy_wstring(lpTempFileName, MAX_PATH, value);
    sink_marker_w("GetTempFileNameW", value);
    if (uUnique == 0)
    {
        flaw_marker_w("GetTempFileNameW", value, "uUnique_zero_creates_then_closes_file");
    }
    return uUnique ? uUnique : 1;
}

DWORD WINAPI GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer)
{
    if (lpBuffer == NULL || nBufferLength == 0)
    {
        return 0;
    }
    if (getcwd(lpBuffer, nBufferLength) == NULL)
    {
        copy_string(lpBuffer, nBufferLength, ".");
    }
    return (DWORD)strlen(lpBuffer);
}

DWORD WINAPI GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer)
{
    char cwd[512];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        copy_string(cwd, sizeof(cwd), ".");
    }
    copy_wstring(lpBuffer, nBufferLength, wide_from_narrow_static(cwd));
    return (DWORD)wcslen(lpBuffer);
}

DWORD WINAPI GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    (void)hModule;
    copy_string(lpFilename, nSize, "case_under_test.exe");
    return lpFilename ? (DWORD)strlen(lpFilename) : 0;
}

DWORD WINAPI GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    (void)hModule;
    copy_wstring(lpFilename, nSize, L"case_under_test.exe");
    return lpFilename ? (DWORD)wcslen(lpFilename) : 0;
}

UINT WINAPI GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize)
{
    copy_string(lpBuffer, uSize, "C:\\Windows");
    return lpBuffer ? (UINT)strlen(lpBuffer) : 0;
}

UINT WINAPI GetWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize)
{
    copy_wstring(lpBuffer, uSize, L"C:\\Windows");
    return lpBuffer ? (UINT)wcslen(lpBuffer) : 0;
}

UINT WINAPI GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize)
{
    copy_string(lpBuffer, uSize, "C:\\Windows\\System32");
    return lpBuffer ? (UINT)strlen(lpBuffer) : 0;
}

UINT WINAPI GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize)
{
    copy_wstring(lpBuffer, uSize, L"C:\\Windows\\System32");
    return lpBuffer ? (UINT)wcslen(lpBuffer) : 0;
}

DWORD WINAPI SearchPathA(LPCSTR lpPath, LPCSTR lpFileName, LPCSTR lpExtension, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart)
{
    (void)lpPath;
    (void)lpExtension;
    copy_string(lpBuffer, nBufferLength, lpFileName ? lpFileName : "found.exe");
    if (lpFilePart != NULL)
    {
        *lpFilePart = lpBuffer;
    }
    sink_marker("SearchPathA", lpBuffer);
    return lpBuffer ? (DWORD)strlen(lpBuffer) : 0;
}

DWORD WINAPI SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart)
{
    (void)lpPath;
    (void)lpExtension;
    copy_wstring(lpBuffer, nBufferLength, lpFileName ? lpFileName : L"found.exe");
    if (lpFilePart != NULL)
    {
        *lpFilePart = lpBuffer;
    }
    sink_marker_w("SearchPathW", lpBuffer);
    return lpBuffer ? (DWORD)wcslen(lpBuffer) : 0;
}

LSTATUS WINAPI RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, HKEY *phkResult)
{
    (void)hKey;
    (void)ulOptions;
    (void)samDesired;
    sink_marker("RegOpenKeyExA", lpSubKey);
    if (phkResult != NULL)
    {
        *phkResult = fake_handle();
    }
    return ERROR_SUCCESS;
}

LSTATUS WINAPI RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, DWORD samDesired, HKEY *phkResult)
{
    (void)hKey;
    (void)ulOptions;
    (void)samDesired;
    sink_marker_w("RegOpenKeyExW", lpSubKey);
    if (phkResult != NULL)
    {
        *phkResult = fake_handle();
    }
    return ERROR_SUCCESS;
}

LSTATUS WINAPI RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY *phkResult)
{
    return RegOpenKeyExA(hKey, lpSubKey, 0, KEY_WRITE, phkResult);
}

LSTATUS WINAPI RegCreateKeyW(HKEY hKey, LPCWSTR lpSubKey, HKEY *phkResult)
{
    return RegOpenKeyExW(hKey, lpSubKey, 0, KEY_WRITE, phkResult);
}

LSTATUS WINAPI RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, DWORD samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, HKEY *phkResult, DWORD *lpdwDisposition)
{
    (void)Reserved;
    (void)lpClass;
    (void)dwOptions;
    (void)lpSecurityAttributes;
    if (lpdwDisposition != NULL)
    {
        *lpdwDisposition = 1;
    }
    return RegOpenKeyExA(hKey, lpSubKey, 0, samDesired, phkResult);
}

LSTATUS WINAPI RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, DWORD samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, HKEY *phkResult, DWORD *lpdwDisposition)
{
    (void)Reserved;
    (void)lpClass;
    (void)dwOptions;
    (void)lpSecurityAttributes;
    if (lpdwDisposition != NULL)
    {
        *lpdwDisposition = 1;
    }
    return RegOpenKeyExW(hKey, lpSubKey, 0, samDesired, phkResult);
}

LSTATUS WINAPI RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
    (void)hKey;
    (void)Reserved;
    (void)dwType;
    (void)lpData;
    (void)cbData;
    sink_marker("RegSetValueExA", lpValueName);
    return ERROR_SUCCESS;
}

LSTATUS WINAPI RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
    (void)hKey;
    (void)Reserved;
    (void)dwType;
    (void)lpData;
    (void)cbData;
    sink_marker_w("RegSetValueExW", lpValueName);
    return ERROR_SUCCESS;
}

LSTATUS WINAPI RegCloseKey(HKEY hKey)
{
    (void)hKey;
    return ERROR_SUCCESS;
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

int _mkdir(const char *path)
{
    return mkdir(path, 0777);
}

int _rmdir(const char *path)
{
    return rmdir(path);
}

char *_getcwd(char *buffer, int maxlen)
{
    return getcwd(buffer, (size_t)maxlen);
}

int _chdir(const char *path)
{
    return chdir(path);
}

int _wmkdir(const wchar_t *path)
{
    char *narrow = narrow_from_wide_alloc(path);
    int result = narrow ? mkdir(narrow, 0777) : -1;
    free(narrow);
    return result;
}

int _wrmdir(const wchar_t *path)
{
    char *narrow = narrow_from_wide_alloc(path);
    int result = narrow ? rmdir(narrow) : -1;
    free(narrow);
    return result;
}

wchar_t *_wgetcwd(wchar_t *buffer, int maxlen)
{
    char cwd[512];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        return NULL;
    }
    copy_wstring(buffer, (size_t)maxlen, wide_from_narrow_static(cwd));
    return buffer;
}

int _wchdir(const wchar_t *path)
{
    char *narrow = narrow_from_wide_alloc(path);
    int result = narrow ? chdir(narrow) : -1;
    free(narrow);
    return result;
}

char *mktemp(char *template_name)
{
    if (replace_x_suffix(template_name, strlen(template_name) + 1) != 0)
    {
        return NULL;
    }
    sink_marker("mktemp", template_name);
    flaw_marker("mktemp", template_name, "temporary_name_created_before_open");
    return template_name;
}

char *tempnam(const char *dir, const char *prefix)
{
    char value[256];
    snprintf(value, sizeof(value), "%s/%sABCDEF", dir ? dir : ".", prefix ? prefix : "tmp");
    sink_marker("tempnam", value);
    flaw_marker("tempnam", value, "temporary_name_created_before_open");
    return strdup(value);
}

char *tmpnam(char *buffer)
{
    static char static_buffer[L_tmpnam];
    char *target = buffer ? buffer : static_buffer;
    copy_string(target, L_tmpnam, "tmpABCDEF");
    sink_marker("tmpnam", target);
    flaw_marker("tmpnam", target, "temporary_name_created_before_open");
    return target;
}

int _mktemp_s(char *template_name, size_t size)
{
    return replace_x_suffix(template_name, size);
}

wchar_t *_wmktemp(wchar_t *template_name)
{
    if (replace_wx_suffix(template_name) != 0)
    {
        return NULL;
    }
    sink_marker_w("_wmktemp", template_name);
    flaw_marker_w("_wmktemp", template_name, "temporary_name_created_before_open");
    return template_name;
}

wchar_t *_wtmpnam(wchar_t *buffer)
{
    static wchar_t static_buffer[L_tmpnam];
    wchar_t *target = buffer ? buffer : static_buffer;
    copy_wstring(target, L_tmpnam, L"tmpABCDEF");
    sink_marker_w("_wtmpnam", target);
    flaw_marker_w("_wtmpnam", target, "temporary_name_created_before_open");
    return target;
}

wchar_t *_wtempnam(const wchar_t *dir, const wchar_t *prefix)
{
    wchar_t value[256];
    swprintf(value, sizeof(value) / sizeof(value[0]), L"%ls/%lsABCDEF", dir ? dir : L".", prefix ? prefix : L"tmp");
    sink_marker_w("_wtempnam", value);
    flaw_marker_w("_wtempnam", value, "temporary_name_created_before_open");
    return wide_strdup_alloc(value);
}

int _open(const char *path, int flags, ...)
{
    int mode = 0666;
    va_list ap;
    if (flags & O_CREAT)
    {
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    sink_marker("_open", path);
    return open(path, flags, mode);
}

int _wopen(const wchar_t *path, int flags, ...)
{
    int mode = 0666;
    char *narrow;
    int result;
    va_list ap;
    if (flags & O_CREAT)
    {
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    narrow = narrow_from_wide_alloc(path);
    sink_marker_w("_wopen", path);
    result = narrow ? open(narrow, flags, mode) : -1;
    free(narrow);
    return result;
}

int _close(int fd)
{
    return close(fd);
}

int _write(int fd, const void *buf, unsigned int count)
{
    return (int)write(fd, buf, count);
}

int _unlink(const char *path)
{
    return unlink(path);
}

int _wunlink(const wchar_t *path)
{
    char *narrow = narrow_from_wide_alloc(path);
    int result = narrow ? unlink(narrow) : -1;
    free(narrow);
    return result;
}

int _access(const char *path, int mode)
{
    return access(path, mode);
}

intptr_t _spawnl(int mode, const char *cmdname, const char *arg0, ...)
{
    intptr_t result;
    va_list ap;
    (void)mode;
    va_start(ap, arg0);
    result = process_marker_varargs_a("_spawnl", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _spawnlp(int mode, const char *cmdname, const char *arg0, ...)
{
    intptr_t result;
    va_list ap;
    (void)mode;
    va_start(ap, arg0);
    result = process_marker_varargs_a("_spawnlp", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _spawnv(int mode, const char *cmdname, const char *const *argv)
{
    (void)mode;
    sink_marker_argv_a("_spawnv", cmdname, argv);
    return 0;
}

intptr_t _spawnvp(int mode, const char *cmdname, const char *const *argv)
{
    (void)mode;
    sink_marker_argv_a("_spawnvp", cmdname, argv);
    return 0;
}

intptr_t _wspawnl(int mode, const wchar_t *cmdname, const wchar_t *arg0, ...)
{
    intptr_t result;
    va_list ap;
    (void)mode;
    va_start(ap, arg0);
    result = process_marker_varargs_w("_wspawnl", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _wspawnlp(int mode, const wchar_t *cmdname, const wchar_t *arg0, ...)
{
    intptr_t result;
    va_list ap;
    (void)mode;
    va_start(ap, arg0);
    result = process_marker_varargs_w("_wspawnlp", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _wspawnv(int mode, const wchar_t *cmdname, const wchar_t *const *argv)
{
    (void)mode;
    sink_marker_argv_w("_wspawnv", cmdname, argv);
    return 0;
}

intptr_t _wspawnvp(int mode, const wchar_t *cmdname, const wchar_t *const *argv)
{
    (void)mode;
    sink_marker_argv_w("_wspawnvp", cmdname, argv);
    return 0;
}

intptr_t _execl(const char *cmdname, const char *arg0, ...)
{
    intptr_t result;
    va_list ap;
    va_start(ap, arg0);
    result = process_marker_varargs_a("_execl", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _execlp(const char *cmdname, const char *arg0, ...)
{
    intptr_t result;
    va_list ap;
    va_start(ap, arg0);
    result = process_marker_varargs_a("_execlp", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _execv(const char *cmdname, const char *const *argv)
{
    sink_marker_argv_a("_execv", cmdname, argv);
    return 0;
}

intptr_t _execvp(const char *cmdname, const char *const *argv)
{
    sink_marker_argv_a("_execvp", cmdname, argv);
    return 0;
}

intptr_t _wexecl(const wchar_t *cmdname, const wchar_t *arg0, ...)
{
    intptr_t result;
    va_list ap;
    va_start(ap, arg0);
    result = process_marker_varargs_w("_wexecl", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _wexeclp(const wchar_t *cmdname, const wchar_t *arg0, ...)
{
    intptr_t result;
    va_list ap;
    va_start(ap, arg0);
    result = process_marker_varargs_w("_wexeclp", cmdname, arg0, ap);
    va_end(ap);
    return result;
}

intptr_t _wexecv(const wchar_t *cmdname, const wchar_t *const *argv)
{
    sink_marker_argv_w("_wexecv", cmdname, argv);
    return 0;
}

intptr_t _wexecvp(const wchar_t *cmdname, const wchar_t *const *argv)
{
    sink_marker_argv_w("_wexecvp", cmdname, argv);
    return 0;
}

uintptr_t _beginthreadex(void *security, unsigned stack_size, unsigned (*start_address)(void *), void *arglist, unsigned initflag, unsigned *thrdaddr)
{
    (void)security;
    (void)stack_size;
    (void)initflag;
    if (thrdaddr != NULL)
    {
        *thrdaddr = 1;
    }
    if (start_address != NULL)
    {
        start_address(arglist);
    }
    return (uintptr_t)fake_handle();
}

void _endthreadex(unsigned retval)
{
    (void)retval;
}

wchar_t *_wgetenv(const wchar_t *name)
{
    char narrow_name[256];
    const char *value;
    wide_to_narrow(name, narrow_name, sizeof(narrow_name));
    value = getenv(narrow_name);
    if (value == NULL)
    {
        value = payload_value();
    }
    return wide_from_narrow_static(value);
}

int _putenv(const char *envstring)
{
    char *copy = envstring ? strdup(envstring) : NULL;
    return copy ? putenv(copy) : -1;
}

int _wputenv(const wchar_t *envstring)
{
    char *copy = narrow_from_wide_alloc(envstring);
    int result = copy ? putenv(copy) : -1;
    return result;
}

int fclose(FILE *stream)
{
    if (stream == NULL)
    {
        flaw_marker("fclose", "", "null_file_pointer_used");
        return EOF;
    }
    return 0;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    (void)ap;
    sink_marker("vsnprintf", format);
    if (str != NULL && size > 0)
    {
        snprintf(str, size, "%s", format == NULL ? "" : format);
    }
    return format == NULL ? 0 : (int)strlen(format);
}

int vswprintf(wchar_t *str, size_t size, const wchar_t *format, va_list ap)
{
    (void)ap;
    sink_marker_w("vswprintf", format);
    if (str != NULL && size > 0)
    {
        swprintf(str, size, L"%ls", format == NULL ? L"" : format);
    }
    return format == NULL ? 0 : (int)wcslen(format);
}

int system(const char *command)
{
    sink_marker("system", command);
    return 0;
}

int _wsystem(const wchar_t *command)
{
    sink_marker_w("_wsystem", command);
    return 0;
}

FILE *popen(const char *command, const char *type)
{
    FILE *file;
    sink_marker("popen", command);
    file = tmpfile();
    if (file != NULL)
    {
        fputs(payload_value(), file);
        rewind(file);
    }
    (void)type;
    return file;
}

int pclose(FILE *stream)
{
    return fclose(stream);
}

FILE *_popen(const char *command, const char *type)
{
    return popen(command, type);
}

FILE *_wpopen(const wchar_t *command, const wchar_t *type)
{
    char narrow[512];
    (void)type;
    wide_to_narrow(command, narrow, sizeof(narrow));
    return popen(narrow, "r");
}

int _pclose(FILE *stream)
{
    return pclose(stream);
}

FILE *_wfopen(const wchar_t *path, const wchar_t *mode)
{
    char *narrow_path = narrow_from_wide_alloc(path);
    char *narrow_mode = narrow_from_wide_alloc(mode);
    FILE *result = NULL;
    if (env_enabled("MAGUS_JULIET_FAIL_WFOPEN"))
    {
        sink_marker_w("_wfopen", path);
        flaw_marker_w("_wfopen", path, "forced_null_return_for_null_deref_check");
        free(narrow_path);
        free(narrow_mode);
        return NULL;
    }
    if (narrow_path != NULL && narrow_mode != NULL)
    {
        result = fopen(narrow_path, narrow_mode);
    }
    free(narrow_path);
    free(narrow_mode);
    return result;
}

int _wrename(const wchar_t *oldname, const wchar_t *newname)
{
    char *old_narrow = narrow_from_wide_alloc(oldname);
    char *new_narrow = narrow_from_wide_alloc(newname);
    int result = (old_narrow && new_narrow) ? rename(old_narrow, new_narrow) : -1;
    free(old_narrow);
    free(new_narrow);
    return result;
}

int _wremove(const wchar_t *path)
{
    char *narrow = narrow_from_wide_alloc(path);
    int result = narrow ? remove(narrow) : -1;
    free(narrow);
    return result;
}

int _putws(const wchar_t *str)
{
    char narrow[1024];
    wide_to_narrow(str, narrow, sizeof(narrow));
    puts(narrow);
    return 0;
}

typedef struct _MAGUS_LDAP {
    int unused;
} MAGUS_LDAP;

typedef struct _MAGUS_LDAP_MESSAGE {
    int unused;
} MAGUS_LDAP_MESSAGE;

LDAP *ldap_initA(const char *host, ULONG port)
{
    (void)port;
    sink_marker("ldap_initA", host);
    return (LDAP *)calloc(1, sizeof(MAGUS_LDAP));
}

LDAP *ldap_initW(const wchar_t *host, ULONG port)
{
    (void)port;
    sink_marker_w("ldap_initW", host);
    return (LDAP *)calloc(1, sizeof(MAGUS_LDAP));
}

ULONG ldap_connect(LDAP *ld, void *timeout)
{
    (void)ld;
    (void)timeout;
    sink_marker("ldap_connect", "");
    return LDAP_SUCCESS;
}

ULONG ldap_search_ext_sA(LDAP *ld, const char *base, ULONG scope, const char *filter, char **attrs, ULONG attrsonly, void *serverctrls, void *clientctrls, ULONG timeout, ULONG sizelimit, LDAPMessage **res)
{
    (void)ld;
    (void)base;
    (void)scope;
    (void)attrs;
    (void)attrsonly;
    (void)serverctrls;
    (void)clientctrls;
    (void)timeout;
    (void)sizelimit;
    sink_marker("ldap_search_ext_sA", filter);
    if (res != NULL)
    {
        *res = (LDAPMessage *)calloc(1, sizeof(MAGUS_LDAP_MESSAGE));
    }
    return LDAP_SUCCESS;
}

ULONG ldap_search_ext_sW(LDAP *ld, const wchar_t *base, ULONG scope, const wchar_t *filter, wchar_t **attrs, ULONG attrsonly, void *serverctrls, void *clientctrls, ULONG timeout, ULONG sizelimit, LDAPMessage **res)
{
    (void)ld;
    (void)base;
    (void)scope;
    (void)attrs;
    (void)attrsonly;
    (void)serverctrls;
    (void)clientctrls;
    (void)timeout;
    (void)sizelimit;
    sink_marker_w("ldap_search_ext_sW", filter);
    if (res != NULL)
    {
        *res = (LDAPMessage *)calloc(1, sizeof(MAGUS_LDAP_MESSAGE));
    }
    return LDAP_SUCCESS;
}

ULONG ldap_search_sA(LDAP *ld, const char *base, ULONG scope, const char *filter, char **attrs, ULONG attrsonly, LDAPMessage **res)
{
    return ldap_search_ext_sA(ld, base, scope, filter, attrs, attrsonly, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, res);
}

ULONG ldap_search_sW(LDAP *ld, const wchar_t *base, ULONG scope, const wchar_t *filter, wchar_t **attrs, ULONG attrsonly, LDAPMessage **res)
{
    return ldap_search_ext_sW(ld, base, scope, filter, attrs, attrsonly, NULL, NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, res);
}

ULONG ldap_msgfree(LDAPMessage *res)
{
    free(res);
    return LDAP_SUCCESS;
}

ULONG ldap_unbind(LDAP *ld)
{
    free(ld);
    return LDAP_SUCCESS;
}

BOOL CryptAcquireContextA(HCRYPTPROV *phProv, LPCSTR pszContainer, LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags)
{
    (void)pszContainer;
    (void)pszProvider;
    (void)dwProvType;
    (void)dwFlags;
    if (phProv != NULL)
    {
        *phProv = fake_handle();
    }
    return TRUE;
}

BOOL CryptAcquireContextW(HCRYPTPROV *phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType, DWORD dwFlags)
{
    (void)pszContainer;
    (void)pszProvider;
    (void)dwProvType;
    (void)dwFlags;
    if (phProv != NULL)
    {
        *phProv = fake_handle();
    }
    return TRUE;
}

BOOL CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags)
{
    (void)hProv;
    (void)dwFlags;
    return TRUE;
}

BOOL CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer)
{
    DWORD i;
    (void)hProv;
    sink_marker("CryptGenRandom", "");
    if (pbBuffer != NULL)
    {
        for (i = 0; i < dwLen; i++)
        {
            pbBuffer[i] = (BYTE)(i + 1);
        }
    }
    return TRUE;
}

BOOL CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash)
{
    (void)hProv;
    (void)hKey;
    (void)dwFlags;
    if (phHash != NULL)
    {
        *phHash = fake_handle();
    }
    if (Algid == CALG_MD2 || Algid == CALG_MD5 || Algid == CALG_SHA1)
    {
        sink_marker("CryptCreateHash", "");
        flaw_marker("CryptCreateHash", "", "broken_hash_algorithm");
    }
    return TRUE;
}

BOOL CryptHashData(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags)
{
    (void)pbData;
    (void)dwDataLen;
    (void)dwFlags;
    if (hHash == NULL)
    {
        flaw_marker("CryptHashData", "", "hash_used_without_create_hash");
    }
    return TRUE;
}

BOOL CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags)
{
    DWORD i;
    DWORD len;
    (void)hHash;
    (void)dwParam;
    (void)dwFlags;
    if (pdwDataLen == NULL)
    {
        return FALSE;
    }
    len = *pdwDataLen;
    if (pbData != NULL)
    {
        for (i = 0; i < len; i++)
        {
            pbData[i] = (BYTE)(0x41 + (i % 26));
        }
    }
    return TRUE;
}

BOOL CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey)
{
    (void)hProv;
    (void)hBaseData;
    (void)dwFlags;
    if (phKey != NULL)
    {
        *phKey = fake_handle();
        register_key(*phKey, Algid);
    }
    if (Algid == CALG_DES || Algid == CALG_3DES || Algid == CALG_RC5)
    {
        sink_marker("CryptDeriveKey", "");
        flaw_marker("CryptDeriveKey", "", "broken_cipher_algorithm");
    }
    return TRUE;
}

BOOL CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen)
{
    (void)hKey;
    (void)hHash;
    (void)Final;
    (void)dwFlags;
    (void)pbData;
    (void)pdwDataLen;
    (void)dwBufLen;
    sink_marker("CryptEncrypt", "");
    if (key_alg(hKey) == CALG_RSA_SIGN && (dwFlags & CRYPT_OAEP) == 0)
    {
        flaw_marker("CryptEncrypt", "", "rsa_without_oaep");
    }
    return TRUE;
}

BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen)
{
    (void)hKey;
    (void)hHash;
    (void)Final;
    (void)dwFlags;
    if (pbData != NULL && pdwDataLen != NULL && *pdwDataLen > 0)
    {
        pbData[*pdwDataLen - 1] = '\0';
    }
    sink_marker("CryptDecrypt", "");
    return TRUE;
}

BOOL CryptDestroyHash(HCRYPTHASH hHash)
{
    (void)hHash;
    return TRUE;
}

BOOL CryptDestroyKey(HCRYPTKEY hKey)
{
    (void)hKey;
    return TRUE;
}

BOOL PathAppendA(LPSTR pszPath, LPCSTR pszMore)
{
    if (pszPath == NULL || pszMore == NULL)
    {
        return FALSE;
    }
    if (pszPath[0] != '\0')
    {
        strncat(pszPath, "\\", MAX_PATH - strlen(pszPath) - 1);
    }
    strncat(pszPath, pszMore, MAX_PATH - strlen(pszPath) - 1);
    sink_marker("PathAppendA", pszPath);
    flaw_marker("PathAppendA", pszPath, "pathappend_requires_max_path_sized_buffer");
    return TRUE;
}

BOOL PathAppendW(LPWSTR pszPath, LPCWSTR pszMore)
{
    if (pszPath == NULL || pszMore == NULL)
    {
        return FALSE;
    }
    if (pszPath[0] != L'\0')
    {
        wcsncat(pszPath, L"\\", MAX_PATH - wcslen(pszPath) - 1);
    }
    wcsncat(pszPath, pszMore, MAX_PATH - wcslen(pszPath) - 1);
    sink_marker_w("PathAppendW", pszPath);
    flaw_marker_w("PathAppendW", pszPath, "pathappend_requires_max_path_sized_buffer");
    return TRUE;
}

LONG SHRegOpenUSKeyA(LPCSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, BOOL fIgnoreHKCU)
{
    (void)samDesired;
    (void)hRelativeUSKey;
    (void)fIgnoreHKCU;
    sink_marker("SHRegOpenUSKeyA", pszPath);
    if (phNewUSKey != NULL)
    {
        *phNewUSKey = fake_handle();
    }
    return ERROR_SUCCESS;
}

LONG SHRegOpenUSKeyW(LPCWSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, BOOL fIgnoreHKCU)
{
    (void)samDesired;
    (void)hRelativeUSKey;
    (void)fIgnoreHKCU;
    sink_marker_w("SHRegOpenUSKeyW", pszPath);
    if (phNewUSKey != NULL)
    {
        *phNewUSKey = fake_handle();
    }
    return ERROR_SUCCESS;
}

LONG SHRegCreateUSKeyA(LPCSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, DWORD dwFlags)
{
    (void)dwFlags;
    return SHRegOpenUSKeyA(pszPath, samDesired, hRelativeUSKey, phNewUSKey, FALSE);
}

LONG SHRegCreateUSKeyW(LPCWSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, DWORD dwFlags)
{
    (void)dwFlags;
    return SHRegOpenUSKeyW(pszPath, samDesired, hRelativeUSKey, phNewUSKey, FALSE);
}

LONG SHRegCloseUSKey(HUSKEY hUSKey)
{
    (void)hUSKey;
    return ERROR_SUCCESS;
}

RPC_STATUS UuidCreate(UUID *Uuid)
{
    if (Uuid != NULL)
    {
        memset(Uuid, 0x42, sizeof(*Uuid));
    }
    sink_marker("UuidCreate", "");
    return RPC_S_OK;
}

RPC_STATUS UuidToStringA(const UUID *Uuid, RPC_CSTR *StringUuid)
{
    (void)Uuid;
    if (StringUuid != NULL)
    {
        *StringUuid = (RPC_CSTR)strdup("42424242-4242-4242-4242-424242424242");
    }
    sink_marker("UuidToStringA", "");
    return RPC_S_OK;
}

RPC_STATUS UuidToStringW(const UUID *Uuid, RPC_WSTR *StringUuid)
{
    (void)Uuid;
    if (StringUuid != NULL)
    {
        *StringUuid = wide_from_narrow_static("42424242-4242-4242-4242-424242424242");
    }
    sink_marker("UuidToStringW", "");
    return RPC_S_OK;
}

RPC_STATUS RpcStringFreeA(RPC_CSTR *String)
{
    if (String != NULL && *String != NULL)
    {
        free(*String);
        *String = NULL;
    }
    return RPC_S_OK;
}

RPC_STATUS RpcStringFreeW(RPC_WSTR *String)
{
    if (String != NULL)
    {
        *String = NULL;
    }
    return RPC_S_OK;
}
