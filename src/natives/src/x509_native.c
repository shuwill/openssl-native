#include "../include/common.h"
#include "../include/com_shuwill_openssl_natives_jni_X509JniNative.h"

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509New
        (JNIEnv *env, jclass class){

    X509 *X509 = X509_new();
    return JLONG(X509);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509Free
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    X509_free(x509);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509NameNew
        (JNIEnv *env, jclass class){

    X509_NAME *name = X509_NAME_new();
    return JLONG(name);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509NameFree
        (JNIEnv *env, jclass class, jlong x){

    X509_NAME *name = X509_NAME(x);
    X509_NAME_free(name);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509NameAddEntryByTxt
        (JNIEnv *env, jclass class, jlong n, jstring f, jint t, jobject b, jint len, jint loc, jint set){

    X509_NAME *name = X509_NAME(n);
    const char *field = (*env)->GetStringUTFChars(env, f, 0);
    const unsigned char *bytes = (*env)->GetDirectBufferAddress(env, b);
    int rersult = X509_NAME_add_entry_by_txt(name, field, t, bytes, len, loc, set);
    (*env)->ReleaseStringUTFChars(env, f, field);
    return rersult;
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509SetVersion
        (JNIEnv *env, jclass class, jlong x, jlong v){

    X509 *x509 = X509(x);
    return X509_set_version(x509, v);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509SetNotBefore
        (JNIEnv *env, jclass class, jlong x, jlong t){

    X509 *x509 = X509(x);
    const ASN1_TIME *tm = ASN1_TIME(t);
    return X509_set1_notBefore(x509, tm);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509SetNotAfter
        (JNIEnv *env, jclass class, jlong x, jlong t){

    X509 *x509 = X509(x);
    const ASN1_TIME *tm = ASN1_TIME(t);
    return X509_set1_notAfter(x509, tm);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509SetSerialNumber
        (JNIEnv *env, jclass class, jlong x, jlong s){

    X509 *x509 = X509(x);
    ASN1_INTEGER *serial = ASN1_INTEGER(s);
    return X509_set_serialNumber(x509, serial);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509SetSubjectName
        (JNIEnv *env, jclass class, jlong x, jlong s){

    X509 *x509 = X509(x);
    X509_NAME *name = X509_NAME(s);
    return X509_set_subject_name(x509, name);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509SetIssuerName
        (JNIEnv *env, jclass class, jlong x, jlong i){

    X509 *x509 = X509(x);
    X509_NAME *name = X509_NAME(i);
    return X509_set_issuer_name(x509, name);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509SetPubkey
        (JNIEnv *env, jclass class, jlong x, jlong p){

    X509 *x509 = X509(x);
    EVP_PKEY *pkey = EVP_PKEY(p);
    return X509_set_pubkey(x509, pkey);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509AddExt
        (JNIEnv *env, jclass class, jlong x, jlong e, jint l){

    X509 *x509 = X509(x);
    X509_EXTENSION *extension = X509_EXTENSION(e);
    return X509_add_ext(x509, extension, l);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ExtensionNew
        (JNIEnv *env, jclass class){

    X509_EXTENSION *extension = X509_EXTENSION_new();
    return JLONG(extension);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ExtensionFree
        (JNIEnv *env, jclass class, jlong e){

    X509_EXTENSION *extension = X509_EXTENSION(e);
    X509_EXTENSION_free(extension);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509V3ExtNconfNid
        (JNIEnv *env, jclass class, jint ext_nid, jstring v, jlong i, jlong s, jlong r, jlong cr, jint flags){

    X509V3_CTX ctx;
    X509 *issuer = X509(i);
    X509 *subject = X509(s);
    X509_REQ *req = X509_REQ(r);
    X509_CRL *crl = X509_CRL(cr);
    X509V3_set_ctx(&ctx, issuer, subject, req, crl, flags);
    const char *value = (*env)->GetStringUTFChars(env, v, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx, ext_nid, value);
    (*env)->ReleaseStringUTFChars(env, v, value);
    return JLONG(ext);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509V3ExtI2d
        (JNIEnv *env, jclass class, jint ext_nid, jint crit, jlong es){

    ASN1_OCTET_STRING *str = ASN1_OCTET_STRING(es);
    X509_EXTENSION *ext = X509V3_EXT_i2d(ext_nid, crit, str);
    return JLONG(ext);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509Sign
        (JNIEnv *env, jclass class, jlong x, jlong p, jlong m){

    X509 *x509 = X509(x);
    EVP_PKEY *pkey = EVP_PKEY(p);
    EVP_MD  *md = EVP_MD(m);
    return X509_sign(x509, pkey, md);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_i2dX509Bio
        (JNIEnv *env, jclass class, jlong b, jlong x){

    BIO *bp = BIO(b);
    X509 *x509 = X509(x);
    return i2d_X509_bio(bp, x509);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_d2iX509Bio
        (JNIEnv *env, jclass class, jlong b){

    BIO *bp = BIO(b);
    X509 *x509 = d2i_X509_bio(bp, NULL);
    return JLONG(x509);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ReqNew
        (JNIEnv *env, jclass class){

    X509_REQ *req = X509_REQ_new();
    return JLONG(req);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ReqFree
        (JNIEnv *env, jclass class, jlong r){

    X509_REQ *req = X509_REQ(r);
    X509_REQ_free(req);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ReqSetSubjectName
        (JNIEnv *env, jclass class, jlong r, jlong s){

    X509_REQ *req = X509_REQ(r);
    X509_NAME *name = X509_NAME(s);
    return X509_REQ_set_subject_name(req, name);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ReqGetSubjectName
        (JNIEnv *env, jclass class, jlong r){

    const X509_REQ *req = X509_REQ(r);
    X509_NAME *name = X509_REQ_get_subject_name(req);
    return JLONG(name);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ReqSetPubkey
        (JNIEnv *env, jclass class, jlong r, jlong p){

    X509_REQ *req = X509_REQ(r);
    EVP_PKEY *pubkey = EVP_PKEY(p);
    return X509_REQ_set_pubkey(req, pubkey);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509ReqSign
        (JNIEnv *env, jclass class, jlong r, jlong p, jlong m){

    X509_REQ *req = X509_REQ(r);
    EVP_PKEY *pkey = EVP_PKEY(p);
    EVP_MD *md = EVP_MD(m);
    return X509_REQ_sign(req, pkey, md);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_i2dX509ReqBio
        (JNIEnv *env, jclass class, jlong b, jlong r){

    BIO *bp = BIO(b);
    X509_REQ *req = X509_REQ(r);
    return i2d_X509_REQ_bio(bp, req);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_d2iX509ReqBio
        (JNIEnv *env, jclass class, jlong b){

    BIO *bp = BIO(b);
    X509_REQ *req = d2i_X509_REQ_bio(bp, NULL);
    return JLONG(req);
}

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509NameOneline
        (JNIEnv *env, jclass class, jlong n){

    X509_NAME *name = X509_NAME(n);
    char buf[8192];
    char *result = X509_NAME_oneline(name, buf, 8192);
    return to_jstring(env, result);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509GetVersion
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    return X509_get_version(x509);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509GetSubjectName
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    X509_NAME *name = X509_get_subject_name(x509);
    return JLONG(name);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509GetIssuerName
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    X509_NAME *name = X509_get_issuer_name(x509);
    return JLONG(name);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509Print
        (JNIEnv *env, jclass class, jlong b, jlong x){

    X509 *x509 = X509(x);
    BIO *bp = BIO(b);
    return X509_print(bp, x509);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509GetX509Pubkey
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(x509);
    return JLONG(pubkey);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_X509JniNative_X509PubkeySetParam
        (JNIEnv *env, jclass class, jlong a, jlong o){

    X509_PUBKEY *pubkey = X509_PUBKEY(a);
    ASN1_OBJECT *aobj = ASN1_OBJECT(o);
    return X509_PUBKEY_set0_param(pubkey, aobj, 0, NULL, NULL, 0);
}
