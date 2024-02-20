package com.shuwill.openssl.common;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.CommonNative;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.X509Native;

public abstract class AbstractNativeEnv implements NativeEnv{

    @Override
    public <T extends CommonNative> T getNativeInterface(Class<T> clazz) {
        final String className = clazz.getName();
        CommonNative nativeInterface = null;
        if(className.equals(CommonNative.class.getName())) {
            nativeInterface = createCommon();
        }
        else if(className.equals(ASN1Native.class.getName())) {
            nativeInterface = createASN1();
        }
        else if(className.equals(EvpNative.class.getName())) {
            nativeInterface = createEvp();
        }
        else if(className.equals(X509Native.class.getName())) {
            nativeInterface = createX509();
        }
        return clazz.cast(nativeInterface);
    }

    protected abstract CommonNative createCommon();

    protected abstract ASN1Native createASN1();

    protected abstract EvpNative createEvp();

    protected abstract X509Native createX509();
}
