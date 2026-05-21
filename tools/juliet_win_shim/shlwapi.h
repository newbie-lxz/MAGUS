#ifndef MAGUS_JULIET_WIN_SHIM_SHLWAPI_H
#define MAGUS_JULIET_WIN_SHIM_SHLWAPI_H

#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOL PathAppendA(LPSTR pszPath, LPCSTR pszMore);
BOOL PathAppendW(LPWSTR pszPath, LPCWSTR pszMore);

LONG SHRegOpenUSKeyA(LPCSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, BOOL fIgnoreHKCU);
LONG SHRegOpenUSKeyW(LPCWSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, BOOL fIgnoreHKCU);
LONG SHRegCreateUSKeyA(LPCSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, DWORD dwFlags);
LONG SHRegCreateUSKeyW(LPCWSTR pszPath, DWORD samDesired, HUSKEY hRelativeUSKey, HUSKEY *phNewUSKey, DWORD dwFlags);
LONG SHRegCloseUSKey(HUSKEY hUSKey);

#ifdef UNICODE
#define PathAppend PathAppendW
#define SHRegOpenUSKey SHRegOpenUSKeyW
#define SHRegCreateUSKey SHRegCreateUSKeyW
#else
#define PathAppend PathAppendA
#define SHRegOpenUSKey SHRegOpenUSKeyA
#define SHRegCreateUSKey SHRegCreateUSKeyA
#endif

#ifdef __cplusplus
}
#endif

#endif
