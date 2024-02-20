package com.shuwill.openssl.common;

import com.shuwill.openssl.natives.CommonNative;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class OpensslNativeEnvironment {

    private final static OpensslNativeEnvironment env = new OpensslNativeEnvironment();
    private final static Map<String, CommonNative> NATIVE_INTERFACE_MAP = new ConcurrentHashMap<>(16);

    private NativeEnv nativeEnv;

    private OpensslNativeEnvironment() {

    }

    public void useJni(String accessLibrary, String opensslLibrary) {
        this.nativeEnv = new JniEnv(accessLibrary, opensslLibrary);
    }

    public void useJna(String opensslLibrary) {
        this.nativeEnv = new JnaEnv(opensslLibrary);
    }

    public <T extends CommonNative> T getNativeInterface(Class<T> clazz) {
        final String clazzName = clazz.getName();
        if(NATIVE_INTERFACE_MAP.containsKey(clazzName)) {
            final CommonNative commonNative = NATIVE_INTERFACE_MAP.get(clazzName);
            return clazz.cast(commonNative);
        }
        if (this.nativeEnv == null) {
            throw new IllegalArgumentException("please init OpensslNativeEnvironment, " +
                    "use OpensslNativeEnvironment.init().useJna or use OpensslNativeEnvironment.init().useJni");
        }
        final T nativeInterface = this.nativeEnv.getNativeInterface(clazz);
        NATIVE_INTERFACE_MAP.put(clazzName, nativeInterface);
        return nativeInterface;
    }

    NativeEnv env() {
        return this.nativeEnv;
    }

    public static OpensslNativeEnvironment init() {
        return env;
    }

    public static OpensslNativeEnvironment get() {
        return env;
    }
}
