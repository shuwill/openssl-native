#include <jni.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define JLONG(addr) ((jlong)((ptrdiff_t)(addr)))

#define BIO_METHOD(addr) ((addr == 0) ? (NULL) : ((BIO_METHOD *)(ptrdiff_t) addr))
#define BIO(addr) ((addr == 0) ? (NULL) : (BIO *)(ptrdiff_t) addr)

#define ASN1_OBJECT(addr) ((addr == 0) ? (NULL) : ((ASN1_OBJECT *)(ptrdiff_t) addr))
#define ASN1_INTEGER(addr) ((addr == 0) ? (NULL) : ((ASN1_INTEGER *)(ptrdiff_t) addr))
#define ASN1_TIME(addr) ((addr == 0) ? (NULL) : ((ASN1_TIME *)(ptrdiff_t) addr))
#define ASN1_OCTET_STRING(addr) ((addr == 0) ? (NULL) : ((ASN1_OCTET_STRING *)(ptrdiff_t) addr))

#define EVP_MD_CTX(addr) ((addr == 0) ? (NULL) : ((EVP_MD_CTX *)(ptrdiff_t) addr))
#define EVP_MD(addr) ((addr == 0) ? (NULL) : ((EVP_MD *)(ptrdiff_t) addr))

#define EVP_CIPHER_CTX(addr) ((addr == 0) ? (NULL) : ((EVP_CIPHER_CTX *)(ptrdiff_t) addr))
#define EVP_CIPHER(addr) ((addr == 0) ? (NULL) : ((EVP_CIPHER *)(ptrdiff_t) addr))

#define EVP_PKEY_CTX(addr) ((addr == 0) ? (NULL) : ((EVP_PKEY_CTX *)(ptrdiff_t) addr))
#define EVP_PKEY(addr) ((addr == 0) ? (NULL) : ((EVP_PKEY *)(ptrdiff_t) addr))
#define PKCS8_PRIV_KEY_INFO(addr) ((addr == 0) ? (NULL) : ((PKCS8_PRIV_KEY_INFO *)(ptrdiff_t) addr))

#define X509(addr) ((addr == 0) ? (NULL) : ((X509 *)(ptrdiff_t) addr))
#define X509_NAME(addr) ((addr == 0) ? (NULL) : ((X509_NAME *)(ptrdiff_t) addr))
#define X509_EXTENSION(addr) ((addr == 0) ? (NULL) : ((X509_EXTENSION *)(ptrdiff_t) addr))
#define X509V3_CTX(addr) ((addr == 0) ? (NULL) : ((X509V3_CTX *)(ptrdiff_t) addr))
#define X509_REQ(addr) ((addr == 0) ? (NULL) : ((X509_REQ *)(ptrdiff_t) addr))
#define X509_CRL(addr) ((addr == 0) ? (NULL) : ((X509_CRL *)(ptrdiff_t) addr))
#define X509_PUBKEY(addr) ((addr == 0) ? (NULL) : ((X509_PUBKEY *)(ptrdiff_t) addr))

#define ENGINE(addr) ((addr == 0) ? (NULL) : ((ENGINE *)(ptrdiff_t) addr))

void to_integer(JNIEnv *, jobject, int);

jcharArray to_jstring(JNIEnv *, const char *);
