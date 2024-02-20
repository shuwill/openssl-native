#include "../include/common.h"
#include "../include/com_shuwill_openssl_natives_jni_CommonJniNative.h"

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioNew
        (JNIEnv *env, jclass class, jlong type) {

    const BIO_METHOD *method = BIO_METHOD(type);
    BIO *bio = BIO_new(method);
    return JLONG(bio);
}


JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioFree
        (JNIEnv *env, jclass class, jlong a) {

    BIO *bio = BIO(a);
    return BIO_free(bio);
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioMem
        (JNIEnv *env, jclass class) {

    const BIO_METHOD *bio_method = BIO_s_mem();
    return JLONG(bio_method);
}

JNIEXPORT void JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioMethFree
        (JNIEnv *env, jclass class, jlong b){

    BIO_METHOD *biom = BIO_METHOD(b);
    BIO_meth_free(biom);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioRead
        (JNIEnv *env, jclass class, jlong b, jobject data, jint dlen) {

    BIO *bio = BIO(b);
    void *data_bytes = (*env)->GetDirectBufferAddress(env, data);
    return BIO_read(bio, data_bytes, dlen);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioReadEx
        (JNIEnv *env, jclass class, jlong b, jobject data, jlong dlen, jobject readed) {

    BIO *bio = BIO(b);
    void *data_bytes = (*env)->GetDirectBufferAddress(env, data);
    size_t readed_len = 0;
    int result = BIO_read_ex(bio, data_bytes, dlen, &readed_len);
    to_integer(env, readed, (int) readed_len);
    return result;
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioWrite
        (JNIEnv *env, jclass class, jlong b, jobject data, jint dlen) {

    BIO *bio = BIO(b);
    const void *data_bytes = (*env)->GetDirectBufferAddress(env, data);
    return BIO_write(bio, data_bytes, dlen);
}

JNIEXPORT jint JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_bioWriteEx
        (JNIEnv *env, jclass class, jlong b, jobject data, jlong dlen, jobject written) {

    BIO *bio = BIO(b);
    const void *data_bytes = (*env)->GetDirectBufferAddress(env, data);
    size_t written_bytes = 0;
    int result = BIO_write_ex(bio, data_bytes, dlen, &written_bytes);
    to_integer(env, written, (int) written_bytes);
    return result;
}

JNIEXPORT jlong JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_errPeekError
        (JNIEnv *env, jclass class) {

    return (jlong) ERR_peek_error();
}

JNIEXPORT jcharArray JNICALL Java_com_shuwill_openssl_natives_jni_CommonJniNative_errString
        (JNIEnv *env, jclass class, jlong err, jcharArray null_) {

    const char *err_desc = ERR_error_string(err, NULL);
    return to_jstring(env, err_desc);
}