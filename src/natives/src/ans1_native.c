#include <string.h>
#include "../include/common.h"
#include "../include/com_shuwill_openssl_natives_jni_ASN1JniNative.h"


JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_nid2obj
        (JNIEnv *env, jclass class, jint n) {

    ASN1_OBJECT *a = OBJ_nid2obj(n);
    return JLONG(a);
}


JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_nid2ln
        (JNIEnv *env, jclass class, jint n) {

    const char *ln = OBJ_nid2ln(n);
    return to_jstring(env, ln);
}


JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_nid2sn
        (JNIEnv *env, jclass class, jint n) {

    const char *sn = OBJ_nid2sn(n);
    return to_jstring(env, sn);
}


JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_obj2nid
        (JNIEnv *env, jclass class, jlong a) {

    ASN1_OBJECT *asn1_obj = ASN1_OBJECT(a);
    return OBJ_obj2nid(asn1_obj);
}


JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_ln2nid
        (JNIEnv *env, jclass clas, jstring ln) {

    const char *s = (*env)->GetStringUTFChars(env, ln, 0);
    int nid = OBJ_ln2nid(s);
    (*env)->ReleaseStringUTFChars(env, ln, s);
    return nid;
}


JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_sn2nid
        (JNIEnv *env, jclass class, jstring sn) {

    const char *s = (*env)->GetStringUTFChars(env, sn, 0);
    int nid = OBJ_sn2nid(s);
    (*env)->ReleaseStringUTFChars(env, sn, s);
    return nid;
}


JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_txt2nid
        (JNIEnv *env, jclass class, jstring txt) {

    const char *s = (*env)->GetStringUTFChars(env, txt, 0);
    int nid = OBJ_txt2nid(s);
    (*env)->ReleaseStringUTFChars(env, txt, s);
    return nid;
}


JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_txt2obj
        (JNIEnv *env, jclass class, jstring txt, jint no_name) {

    const char *s = (*env)->GetStringUTFChars(env, txt, 0);
    ASN1_OBJECT *obj = OBJ_txt2obj(s, no_name);
    (*env)->ReleaseStringUTFChars(env, txt, s);
    return JLONG(obj);
}


JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_obj2txt
        (JNIEnv *env, jclass clas, jobject buf, jint buf_len, jlong a, jint no_name) {

    char *buffer = (char *)(*env)->GetDirectBufferAddress(env, buf);
    return OBJ_obj2txt(buffer, buf_len, ASN1_OBJECT(a), no_name);
}


JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_cmp
        (JNIEnv *env, jclass class, jlong a, jlong b) {

    return OBJ_cmp(ASN1_OBJECT(a), ASN1_OBJECT(a));
}


JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1ObjectNew
        (JNIEnv *env, jclass class) {

    ASN1_OBJECT *obj = ASN1_OBJECT_new();
    return JLONG(obj);
}


JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1ObjectFree
        (JNIEnv *env, jclass class, jlong a) {

    ASN1_OBJECT *obj = ASN1_OBJECT(a);
    ASN1_OBJECT_free(obj);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1TimeNew
        (JNIEnv *env, jclass class){

    ASN1_TIME *time = ASN1_TIME_new();
    return JLONG(time);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1TimeSetString
        (JNIEnv *env, jclass class, jlong t, jstring s){

    ASN1_TIME *time = ASN1_TIME(t);
    const char *str = (*env)->GetStringUTFChars(env, s, 0);
    int result = ASN1_TIME_set_string(time, str);
    (*env)->ReleaseStringUTFChars(env, s, str);
    return result;
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GmtimeAdj
        (JNIEnv *env, jclass class, jlong t, jlong v){

    ASN1_TIME *tm = t == 0 ? NULL : ASN1_TIME(t);
    ASN1_TIME *time = X509_gmtime_adj(tm, v);
    return JLONG(time);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1TimeFree
        (JNIEnv *env, jclass class, jlong a){

    ASN1_TIME *time = ASN1_TIME(a);
    ASN1_TIME_free(time);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1IntegerNew
        (JNIEnv *env, jclass a){

    ASN1_INTEGER *integer = ASN1_INTEGER_new();
    return JLONG(integer);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1IntegerSet
        (JNIEnv *env, jclass class, jlong a, jlong v){

    ASN1_INTEGER *integer = ASN1_INTEGER(a);
    return ASN1_INTEGER_set(integer, v);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1IntegerFree
        (JNIEnv *env, jclass class, jlong a){

    ASN1_INTEGER *integer = ASN1_INTEGER(a);
    ASN1_INTEGER_free(integer);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1OctetStringNew
        (JNIEnv *env, jclass a){

    ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
    return JLONG(str);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1OctetStringSet
        (JNIEnv *env, jclass class, jlong a, jobject s, jint l){

    const unsigned char *data = (*env)->GetDirectBufferAddress(env, s);
    ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
    return ASN1_OCTET_STRING_set(str,data, l);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1OctetStringFree
        (JNIEnv *env, jclass class, jlong a){

    ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_free(str);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GetNotBefore
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    const ASN1_TIME *time = X509_get0_notAfter(x509);
    return JLONG(time);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GetNotAfter
        (JNIEnv *env, jclass class, jlong x){

    X509 *x509 = X509(x);
    const ASN1_TIME *time = X509_get0_notAfter(x509);
    return JLONG(time);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GetSerialNumber
        (JNIEnv *env, jclass class, jlong x) {

    X509 *x509 = X509(x);
    const ASN1_INTEGER *serialNumber= X509_get0_serialNumber(x509);
    return JLONG(serialNumber);
}