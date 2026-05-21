#ifndef MAGUS_JULIET_WIN_SHIM_WINLDAP_H
#define MAGUS_JULIET_WIN_SHIM_WINLDAP_H

#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _MAGUS_LDAP LDAP;
typedef struct _MAGUS_LDAP_MESSAGE LDAPMessage;

#define LDAP_PORT 389
#define LDAP_SUCCESS 0
#define LDAP_SCOPE_SUBTREE 2
#define LDAP_NO_LIMIT 0

LDAP *ldap_initA(const char *host, ULONG port);
LDAP *ldap_initW(const wchar_t *host, ULONG port);
ULONG ldap_connect(LDAP *ld, void *timeout);
ULONG ldap_search_ext_sA(
    LDAP *ld,
    const char *base,
    ULONG scope,
    const char *filter,
    char **attrs,
    ULONG attrsonly,
    void *serverctrls,
    void *clientctrls,
    ULONG timeout,
    ULONG sizelimit,
    LDAPMessage **res);
ULONG ldap_search_ext_sW(
    LDAP *ld,
    const wchar_t *base,
    ULONG scope,
    const wchar_t *filter,
    wchar_t **attrs,
    ULONG attrsonly,
    void *serverctrls,
    void *clientctrls,
    ULONG timeout,
    ULONG sizelimit,
    LDAPMessage **res);
ULONG ldap_search_sA(LDAP *ld, const char *base, ULONG scope, const char *filter, char **attrs, ULONG attrsonly, LDAPMessage **res);
ULONG ldap_search_sW(LDAP *ld, const wchar_t *base, ULONG scope, const wchar_t *filter, wchar_t **attrs, ULONG attrsonly, LDAPMessage **res);
ULONG ldap_msgfree(LDAPMessage *res);
ULONG ldap_unbind(LDAP *ld);

#ifdef __cplusplus
}
#endif

#endif
