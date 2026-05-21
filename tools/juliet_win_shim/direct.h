#ifndef MAGUS_JULIET_WIN_SHIM_DIRECT_H
#define MAGUS_JULIET_WIN_SHIM_DIRECT_H

#include <stddef.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

int _mkdir(const char *path);
int _rmdir(const char *path);
char *_getcwd(char *buffer, int maxlen);
int _chdir(const char *path);

int _wmkdir(const wchar_t *path);
int _wrmdir(const wchar_t *path);
wchar_t *_wgetcwd(wchar_t *buffer, int maxlen);
int _wchdir(const wchar_t *path);

#ifdef __cplusplus
}
#endif

#endif
