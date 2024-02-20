/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_shuwill_openssl_natives_jni_CommonJniNative */

#ifndef _Included_com_shuwill_openssl_natives_jni_CommonJniNative
#define _Included_com_shuwill_openssl_natives_jni_CommonJniNative
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioNew
  (JNIEnv *, jclass, jlong);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioFree
  (JNIEnv *, jclass, jlong);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioMem
  (JNIEnv *, jclass);

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioMethFree
        (JNIEnv *, jclass, jlong);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioRead
  (JNIEnv *, jclass, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioReadEx
  (JNIEnv *, jclass, jlong, jobject, jlong, jobject);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioWrite
  (JNIEnv *, jclass, jlong, jobject, jint);

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioWriteEx
  (JNIEnv *, jclass, jlong, jobject, jlong, jobject);

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_errPeekError
  (JNIEnv *, jclass);

JNIEXPORT jstring JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_errString
  (JNIEnv *, jclass, jlong, jcharArray);

#ifdef __cplusplus
}
#endif
#endif