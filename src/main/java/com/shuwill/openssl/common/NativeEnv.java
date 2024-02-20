package com.shuwill.openssl.common;

import com.shuwill.openssl.natives.CommonNative;

interface NativeEnv {

    <T extends CommonNative> T getNativeInterface(Class<T> clazz);
}
