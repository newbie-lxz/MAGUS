#ifndef MAGUS_JULIET_WIN_SHIM_WINCRYPT_H
#define MAGUS_JULIET_WIN_SHIM_WINCRYPT_H

#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROV_RSA_FULL 1
#define PROV_RSA_AES 24
#define CRYPT_NEWKEYSET 0x00000008UL
#define CRYPT_OAEP 0x00000040UL
#define MS_ENHANCED_PROV "Microsoft Enhanced Cryptographic Provider"
#define MS_ENHANCED_PROV_A "Microsoft Enhanced Cryptographic Provider"
#define MS_ENHANCED_PROV_W L"Microsoft Enhanced Cryptographic Provider"
#define MS_ENH_RSA_AES_PROV "Microsoft Enhanced RSA and AES Cryptographic Provider"
#define MS_ENH_RSA_AES_PROV_A "Microsoft Enhanced RSA and AES Cryptographic Provider"
#define MS_ENH_RSA_AES_PROV_W L"Microsoft Enhanced RSA and AES Cryptographic Provider"

#define ALG_CLASS_DATA_ENCRYPT 0x6000
#define ALG_CLASS_HASH 0x8000
#define ALG_TYPE_BLOCK 0x0600
#define ALG_TYPE_ANY 0
#define ALG_SID_DES 1
#define ALG_SID_3DES 3
#define ALG_SID_RC5 13
#define ALG_SID_MD2 1
#define ALG_SID_MD5 3
#define ALG_SID_SHA1 4
#define ALG_SID_SHA_256 12
#define ALG_SID_AES_256 16
#define ALG_SID_RSA_ANY 0
#define ALG_SID_RSA_SIGN 2

#define CALG_DES (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DES)
#define CALG_3DES (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES)
#define CALG_RC5 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC5)
#define CALG_AES_256 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256)
#define CALG_RSA_SIGN (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_ANY | ALG_SID_RSA_SIGN)
#define CALG_MD2 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2)
#define CALG_MD5 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5)
#define CALG_SHA1 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1)
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)

#define HP_HASHVAL 0x0002

BOOL CryptAcquireContextA(HCRYPTPROV *phProv, LPCSTR pszContainer, LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags);
BOOL CryptAcquireContextW(HCRYPTPROV *phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType, DWORD dwFlags);
BOOL CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
BOOL CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);
BOOL CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
BOOL CryptHashData(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
BOOL CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
BOOL CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey);
BOOL CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);
BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
BOOL CryptDestroyHash(HCRYPTHASH hHash);
BOOL CryptDestroyKey(HCRYPTKEY hKey);

#ifdef UNICODE
#define CryptAcquireContext CryptAcquireContextW
#else
#define CryptAcquireContext CryptAcquireContextA
#endif

#ifdef __cplusplus
}
#endif

#endif
