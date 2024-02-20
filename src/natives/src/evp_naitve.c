#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "../include/common.h"
#include "../include/com_shuwill_openssl_natives_jni_EvpJniNative.h"

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdCtxNew
        (JNIEnv *env, jclass class) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    return JLONG(ctx);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdCtxReset
        (JNIEnv *env, jclass class, jlong c) {

    EVP_MD_CTX *ctx = EVP_MD_CTX(c);
    EVP_MD_CTX_reset(ctx);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdCtxFree
        (JNIEnv *env, jclass class, jlong c) {

    EVP_MD_CTX *ctx = EVP_MD_CTX(c);
    EVP_MD_CTX_free(ctx);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpGetDigestByName
        (JNIEnv *env, jclass class, jstring n) {

    const char *name = (*env)->GetStringUTFChars(env, n, 0);
    const EVP_MD *md = EVP_get_digestbyname(name);
    (*env)->ReleaseStringUTFChars(env, n, name);
    return JLONG(md);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpGetDigestByNid
        (JNIEnv *env, jclass class, jint n) {

    const EVP_MD *md = EVP_get_digestbynid(n);
    return JLONG(md);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpGetDigestByObj
        (JNIEnv *env, jclass class, jlong o) {

    ASN1_OBJECT *obj = ASN1_OBJECT(o);
    const EVP_MD *md = EVP_get_digestbyobj(obj);
    return JLONG(md);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdFree
        (JNIEnv *env, jclass class, jlong m) {

    EVP_MD *md = EVP_MD(m);
    EVP_MD_free(md);
}

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdGetName
        (JNIEnv *env, jclass class, jlong m) {

    const EVP_MD *md = EVP_MD(m);
    const char *name = EVP_MD_get0_name(md);
    return to_jstring(env, name);
}

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdGetDescription
        (JNIEnv *env, jclass class, jlong m) {

    if (m == 0) {
        return NULL;
    }
    const EVP_MD *md = EVP_MD(m);
    const char *desc = EVP_MD_get0_description(md);
    return to_jstring(env, desc);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdGetSize
        (JNIEnv *env, jclass class, jlong m) {

    const EVP_MD *md = EVP_MD(m);
    return EVP_MD_get_size(md);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpMdCtxGetSize
        (JNIEnv *env, jclass class, jlong c) {

    EVP_MD_CTX *ctx = EVP_MD_CTX(c);
    return EVP_MD_CTX_get_size(ctx);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpDigestInit
        (JNIEnv *env, jclass class, jlong c, jlong m) {

    EVP_MD_CTX *ctx = EVP_MD_CTX(c);
    const EVP_MD *md = EVP_MD(m);
    return EVP_DigestInit(ctx, md);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpDigestUpdate
        (JNIEnv *env, jclass class, jlong c, jobject d, jint s) {

    EVP_MD_CTX *ctx = EVP_MD_CTX(c);
    const void *buffer = (*env)->GetDirectBufferAddress(env, d);
    return EVP_DigestUpdate(ctx, buffer, s);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpDigestFinal
        (JNIEnv *env, jclass class, jlong c, jobject out, jobject s) {

    EVP_MD_CTX *ctx = EVP_MD_CTX(c);
    unsigned char *md = (*env)->GetDirectBufferAddress(env, out);
    unsigned int size = 0;
    int result = EVP_DigestFinal_ex(ctx, md, &size);
    to_integer(env, s, (int) size);
    return result;
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherCtxNew
        (JNIEnv *env, jclass class) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    return JLONG(ctx);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherCtxReset
        (JNIEnv *env, jclass class, jlong c) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    return EVP_CIPHER_CTX_reset(ctx);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherCtxFree
        (JNIEnv *env, jclass class, jlong c) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    EVP_CIPHER_CTX_free(ctx);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpGetCipherByName
        (JNIEnv *env, jclass class, jstring n) {

    const char *name = (*env)->GetStringUTFChars(env, n, 0);
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(name);
    (*env)->ReleaseStringUTFChars(env, n, name);
    return JLONG(cipher);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpGetCipherByNid
        (JNIEnv *env, jclass class, jint n) {

    const EVP_CIPHER *cipher = EVP_get_cipherbynid(n);
    return JLONG(cipher);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpGetCipherByObj
        (JNIEnv *env, jclass class, jlong o) {

    ASN1_OBJECT *obj = ASN1_OBJECT(o);
    const EVP_CIPHER *cipher = EVP_get_cipherbyobj(obj);
    return JLONG(cipher);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherFree
        (JNIEnv *env, jclass class, jlong c) {

    EVP_CIPHER *cipher = EVP_CIPHER(c);
    EVP_CIPHER_free(cipher);
}

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherGetName
        (JNIEnv *env, jclass class, jlong c) {

    if (c == 0) {
        return NULL;
    }
    const EVP_CIPHER *cipher = EVP_CIPHER(c);
    const char *name = EVP_CIPHER_get0_name(cipher);
    return to_jstring(env, name);
}

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherGetDescription
        (JNIEnv *env, jclass class, jlong c) {

    if (c == 0) {
        return NULL;
    }
    const EVP_CIPHER *cipher = EVP_CIPHER(c);
    const char *desc = EVP_CIPHER_get0_description(cipher);
    return to_jstring(env, desc);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherGetBlocksize
        (JNIEnv *env, jclass class, jlong c) {
    if (c == 0) {
        return -1;
    }
    const EVP_CIPHER *cipher = EVP_CIPHER(c);
    return EVP_CIPHER_get_block_size(cipher);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherGetMode
        (JNIEnv *env, jclass class, jlong c) {

    if (c == 0) {
        return -1;
    }
    const EVP_CIPHER *cipher = EVP_CIPHER(c);
    return EVP_CIPHER_get_mode(cipher);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherIs
        (JNIEnv *env, jclass class, jlong c, jstring n) {

    const EVP_CIPHER *cipher = EVP_CIPHER(c);
    const char *name = (*env)->GetStringUTFChars(env, n, 0);
    int result = EVP_CIPHER_is_a(cipher, name);
    (*env)->ReleaseStringUTFChars(env, n, name);
    return result;
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherGetKeyLength
        (JNIEnv *env, jclass class, jlong c) {

    if (c == 0) {
        return 0;
    }
    const EVP_CIPHER *cipher = EVP_CIPHER(c);
    return EVP_CIPHER_get_key_length(cipher);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherCtxGetKeyLength
        (JNIEnv *env, jclass class, jlong c) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    return EVP_CIPHER_CTX_get_key_length(ctx);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherCtxSetKeyLength
        (JNIEnv *env, jclass class, jlong c, jint kenlen) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    return EVP_CIPHER_CTX_set_key_length(ctx, kenlen);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherCtxSetPadding
        (JNIEnv *env, jclass class, jlong c, jint pad) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    return EVP_CIPHER_CTX_set_padding(ctx, pad);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherGetIvLength
        (JNIEnv *env, jclass class, jlong c) {

    if (c == 0) {
        return 0;
    }
    const EVP_CIPHER *cipher = EVP_CIPHER(c);
    return EVP_CIPHER_get_iv_length(cipher);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherCtxGetIvLength
        (JNIEnv *env, jclass class, jlong c) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    return EVP_CIPHER_CTX_get_iv_length(ctx);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpBytesToKey
        (JNIEnv *env, jclass class, jlong c, jlong m, jobject s, jobject d, jint datal, jint count, jobject k,
         jobject i) {

    if (c == 0) {
        return 0;
    }
    const EVP_CIPHER *type = EVP_CIPHER(c);
    EVP_MD *md = EVP_MD(m);

    unsigned char *salt = s == NULL ? NULL : (*env)->GetDirectBufferAddress(env, s);
    unsigned char *data = (*env)->GetDirectBufferAddress(env, d);

    unsigned char *key = (*env)->GetDirectBufferAddress(env, k);
    unsigned char *iv = (*env)->GetDirectBufferAddress(env, i);
    return EVP_BytesToKey(type, md, salt, data, datal, count, key, iv);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherInit
        (JNIEnv *env, jclass class, jlong ct, jlong ci, jobject k, jobject i, jint enc) {

    unsigned char *key = (*env)->GetDirectBufferAddress(env, k);
    unsigned char *iv = (*env)->GetDirectBufferAddress(env, i);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(ct);
    const EVP_CIPHER *cipher = EVP_CIPHER(ci);

    return EVP_CipherInit(ctx, cipher, key, iv, enc);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherUpdate
        (JNIEnv *env, jclass class, jlong c, jobject o, jobject ol, jobject i, jint inl) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    unsigned char *out = (*env)->GetDirectBufferAddress(env, o);
    int outl = 0;
    unsigned char *in = (*env)->GetDirectBufferAddress(env, i);
    int result = EVP_CipherUpdate(ctx, out, &outl, in, inl);
    to_integer(env, ol, outl);
    return result;
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpCipherFinal
        (JNIEnv *env, jclass class, jlong c, jobject o, jobject ol) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX(c);
    unsigned char *out = (*env)->GetDirectBufferAddress(env, o);
    int outl = 0;
    int result = EVP_CipherFinal_ex(ctx, out, &outl);
    to_integer(env, ol, outl);
    return result;
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyCtxNewId
        (JNIEnv *env, jclass class, jint i, jlong e) {

    ENGINE *engine = ENGINE(e);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(i, engine);
    return JLONG(ctx);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyCtxNew
        (JNIEnv *env, jclass class, jlong p, jlong e) {

    EVP_PKEY *pkey = EVP_PKEY(p);
    ENGINE *engine = ENGINE(e);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, engine);
    return JLONG(ctx);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyCtxFree
        (JNIEnv *env, jclass class, jlong c) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    EVP_PKEY_CTX_free(ctx);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyNew
        (JNIEnv *env, jclass class) {

    EVP_PKEY *pkey = EVP_PKEY_new();
    return JLONG(pkey);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyFree
        (JNIEnv *env, jclass class, jlong p) {

    EVP_PKEY *pkey = EVP_PKEY(p);
    EVP_PKEY_free(pkey);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyCtxIs
        (JNIEnv *env, jclass class, jlong c, jstring t) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    const char *keytype = (*env)->GetStringUTFChars(env, t, 0);
    int result = EVP_PKEY_CTX_is_a(ctx, keytype);
    (*env)->ReleaseStringUTFChars(env, t, keytype);
    return result;
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyKeygenInit
        (JNIEnv *env, jclass class, jlong c) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    return EVP_PKEY_keygen_init(ctx);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyParamgenInit
        (JNIEnv *env, jclass class, jlong c) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    return EVP_PKEY_paramgen_init(ctx);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyGenerate
        (JNIEnv *env, jclass class, jlong c, jlong p) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    EVP_PKEY *pkey = EVP_PKEY(p);
    return EVP_PKEY_generate(ctx, &pkey);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyParamgen
        (JNIEnv *env, jclass class, jlong c, jlong p) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    EVP_PKEY *pkey = EVP_PKEY(p);
    return EVP_PKEY_paramgen(ctx, &pkey);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyKeygen
        (JNIEnv *env, jclass class, jlong c, jlong p) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    EVP_PKEY *pkey = EVP_PKEY(p);
    return EVP_PKEY_keygen(ctx, &pkey);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyCtxSetRsaKeygenBits
        (JNIEnv *env, jclass class, jlong c, jint bits) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyCtxSetEcParamgenCurveNid
        (JNIEnv *env, jclass class, jlong c, jint nid) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeyCtxSetEcParamenc
        (JNIEnv *env, jclass class, jlong c, jint param_enc) {

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX(c);
    return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkey2Pkcs8
        (JNIEnv *env, jclass class, jlong p){

    EVP_PKEY *pkey = EVP_PKEY(p);
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(pkey);
    return JLONG(p8);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_i2dPkcs8PrivkeyInfoBio
        (JNIEnv *env, jclass class, jlong bp , jlong p){

    BIO *bio = BIO(bp);
    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO(p);
    return i2d_PKCS8_PRIV_KEY_INFO_bio(bio, p8);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_d2iPkcs8PrivkeyInfoBio
        (JNIEnv *env, jclass class, jlong bp){

    BIO *bio = BIO(bp);
    PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO_bio(bio, NULL);
    return JLONG(p8);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkcs82Pkey
        (JNIEnv *env, jclass class, jlong p){

    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO(p);
    EVP_PKEY *pkey = EVP_PKCS82PKEY(p8);
    return JLONG(pkey);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_pkcs8PrivkeyInfoFree
        (JNIEnv *env, jclass class, jlong p){

    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO(p);
    PKCS8_PRIV_KEY_INFO_free(p8);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_i2dPubkeyBio
        (JNIEnv *env, jclass class, jlong b, jlong k) {

    BIO *bp = BIO(b);
    EVP_PKEY *pkey = EVP_PKEY(k);
    return i2d_PUBKEY_bio(bp, pkey);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_d2iPubkeyBio
        (JNIEnv *env, jclass class, jlong b){

    BIO *bp = BIO(b);
    EVP_PKEY *pkey = d2i_PUBKEY_bio(bp, NULL);
    return JLONG(pkey);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_X509ReqGetPubkey
        (JNIEnv *env, jclass class, jlong r){

    X509_REQ *req = X509_REQ(r);
    EVP_PKEY *pkey = X509_REQ_get0_pubkey(req);
    return JLONG(pkey);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_X509GetPubkey
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    return JLONG(pkey);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_PEMWriteBioPKCS8PrivateKey
        (JNIEnv *env, jclass class, jlong b, jlong p, jlong c, jobject pwd){

    BIO *bp = BIO(b);
    EVP_PKEY *pkey = EVP_PKEY(p);
    EVP_CIPHER *cipher = EVP_CIPHER(c);
    void *password = (*env)->GetDirectBufferAddress(env, pwd);
    return PEM_write_bio_PKCS8PrivateKey(bp, pkey, cipher, NULL, 0, NULL, password);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_i2dPKCS8PrivateKeyNidBio
        (JNIEnv *env, jclass class, jlong b, jlong p, jint nid, jobject pwd){

    BIO *bp = BIO(b);
    EVP_PKEY *pkey = EVP_PKEY(p);
    void *password = (*env)->GetDirectBufferAddress(env, pwd);
    return i2d_PKCS8PrivateKey_nid_bio(bp, pkey, nid, NULL, 0, NULL, password);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_EvpJniNative_evpPkeySetType
        (JNIEnv *env, jclass class, jlong p, jint type) {
    EVP_PKEY *pkey = EVP_PKEY(p);
    return EVP_PKEY_set_type(pkey, type);
}