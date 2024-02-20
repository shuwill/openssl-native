/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_shuwill_openssl_natives_jni_ASN1JniNative */

#ifndef _Included_com_shuwill_openssl_natives_jni_ASN1JniNative
#define _Included_com_shuwill_openssl_natives_jni_ASN1JniNative
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_nid2obj
  (JNIEnv *, jclass, jint);

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_nid2ln
  (JNIEnv *, jclass, jint);

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_nid2sn
  (JNIEnv *, jclass, jint);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_obj2nid
  (JNIEnv *, jclass, jlong);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_ln2nid
  (JNIEnv *, jclass, jstring);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_sn2nid
  (JNIEnv *, jclass, jstring);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_txt2nid
  (JNIEnv *, jclass, jstring);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_txt2obj
  (JNIEnv *, jclass, jstring, jint);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_obj2txt
  (JNIEnv *, jclass, jobject, jint, jlong, jint);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_cmp
  (JNIEnv *, jclass, jlong, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1ObjectNew
  (JNIEnv *, jclass);

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1ObjectFree
  (JNIEnv *, jclass, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1TimeNew
  (JNIEnv *, jclass);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1TimeSetString
        (JNIEnv *, jclass, jlong, jstring);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GmtimeAdj
        (JNIEnv *, jclass, jlong, jlong);

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1TimeFree
  (JNIEnv *, jclass, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1IntegerNew
  (JNIEnv *, jclass);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1IntegerSet
  (JNIEnv *, jclass, jlong, jlong);

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1IntegerFree
  (JNIEnv *, jclass, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1OctetStringNew
  (JNIEnv *, jclass);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1OctetStringSet
  (JNIEnv *, jclass, jlong, jobject, jint);

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_asn1OctetStringFree
  (JNIEnv *, jclass, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GetNotBefore
        (JNIEnv *, jclass, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GetNotAfter
        (JNIEnv *, jclass, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_ASN1JniNative_X509GetSerialNumber
        (JNIEnv *, jclass, jlong);

#ifdef __cplusplus
}
#endif
#endif
