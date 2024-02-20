#include <jni.h>
#include <string.h>

void to_integer(JNIEnv *env, jobject object, int value) {
    jclass native_int_class = (*env)->GetObjectClass(env, object);
    jfieldID jfield_id = (*env)->GetFieldID(env, native_int_class, "value", "I");
    (*env)->SetIntField(env, object, jfield_id, value);
}

jstring to_jstring(JNIEnv *env, const char *str) {
    if(str == NULL) {
        return NULL;
    }
    jclass string_class = (*env)->FindClass(env, "Ljava/lang/String;");
    jmethodID ctorID = (*env)->GetMethodID(env, string_class, "<init>", "([B)V");

    jbyteArray bytes = (*env)->NewByteArray(env, (jsize) strlen(str));
    (*env)->SetByteArrayRegion(env, bytes, 0, (jsize) strlen(str), (jbyte *) str);

    jstring result =(jstring) (*env)->NewObject(env, string_class, ctorID, bytes);
    (*env) -> DeleteLocalRef(env, bytes);

    return result;
}