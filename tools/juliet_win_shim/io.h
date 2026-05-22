#ifndef MAGUS_JULIET_WIN_SHIM_IO_H
#define MAGUS_JULIET_WIN_SHIM_IO_H

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

#ifndef _O_RDONLY
#define _O_RDONLY 00
#endif
#ifndef _O_WRONLY
#define _O_WRONLY 01
#endif
#ifndef _O_RDWR
#define _O_RDWR 02
#endif
#ifndef _O_CREAT
#define _O_CREAT 0100
#endif
#ifndef _O_EXCL
#define _O_EXCL 0200
#endif
#ifndef _O_TRUNC
#define _O_TRUNC 01000
#endif
#ifndef _S_IREAD
#define _S_IREAD 0400
#endif
#ifndef _S_IWRITE
#define _S_IWRITE 0200
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAGUS_JULIET_WIN_SHIM_ERRNO_T
#define MAGUS_JULIET_WIN_SHIM_ERRNO_T
typedef int errno_t;
#endif

errno_t _mktemp_s(char *template_name, size_t size);
wchar_t *_wmktemp(wchar_t *template_name);
wchar_t *_wtmpnam(wchar_t *buffer);
wchar_t *_wtempnam(const wchar_t *dir, const wchar_t *prefix);
int _open(const char *path, int flags, ...);
int _wopen(const wchar_t *path, int flags, ...);
int _close(int fd);
int _write(int fd, const void *buf, unsigned int count);
int _unlink(const char *path);
int _wunlink(const wchar_t *path);
int _access(const char *path, int mode);
FILE *_wfopen(const wchar_t *path, const wchar_t *mode);

#ifdef __cplusplus
}
#endif

#endif
