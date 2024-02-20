#include<stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "../include/common.h"

int main() {
    BIO *bio = BIO_new(BIO_s_mem());

    const char *source = "test";
    int written = 0;
    BIO_write_ex(bio, source, strlen(source), (size_t *) &written);
    printf("writt count is %d\n", written);

    char buffer[1024];
    BIO_gets(bio, (char *) buffer, sizeof(buffer));
    printf("%s\n", buffer);

    BIO_free(bio);

    int nid = OBJ_sn2nid("MD5");
    printf("%d\n", nid);
    const EVP_MD *md = EVP_get_digestbynid(nid);
    const char *md_name = EVP_MD_get0_description(md);
    if (md_name == NULL) {
        printf("null\n");
    }
    printf("%s\n", md_name);

    int rsa_nid = OBJ_txt2nid("rsaEncryption");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(rsa_nid, NULL);
    EVP_PKEY_keygen_init(ctx);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_generate(ctx, &pkey);

    PKCS8_PRIV_KEY_INFO *pkcs8_pri_key_info = EVP_PKEY2PKCS8(pkey);

    BIO *bio_pk = BIO_new(BIO_s_mem());
    i2d_PKCS8_PRIV_KEY_INFO_bio(bio_pk, pkcs8_pri_key_info);
    // i2d_PKCS8PrivateKey_bio(bio_pk, pkey, NULL, NULL, 0, NULL, NULL);
    unsigned char pk_buffer[8192];
    int readsize = 0;
    BIO_read_ex(bio_pk, pk_buffer, sizeof(pk_buffer), &readsize);
    PKCS8_PRIV_KEY_INFO_free(pkcs8_pri_key_info);

    char pk_result[readsize];
    memcpy(pk_result, pk_buffer, sizeof pk_result);

    BIO *bio_parse_pk = BIO_new(BIO_s_mem());
    BIO_write(bio_parse_pk, pk_result, sizeof pk_result);
    //EVP_PKEY *parse_pkey = d2i_PKCS8PrivateKey_bio(bio_parse_pk, NULL, NULL, NULL);
    PKCS8_PRIV_KEY_INFO *parse_pkcs8_pri_key_info = d2i_PKCS8_PRIV_KEY_INFO_bio(bio_parse_pk, NULL);
    EVP_PKEY *parse_pkey = EVP_PKCS82PKEY(parse_pkcs8_pri_key_info);

    unsigned long err = ERR_peek_error();
    const char *reason = ERR_reason_error_string(err);


    printf("%s\n", reason);
}