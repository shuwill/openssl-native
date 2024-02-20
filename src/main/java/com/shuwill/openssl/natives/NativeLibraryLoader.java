package com.shuwill.openssl.natives;

import com.sun.jna.Library;
import com.sun.jna.Native;

public class NativeLibraryLoader {

    private static NativeLibraryLoader that;

    private NativeLibraryLoader() {

    }

    public static NativeLibraryLoader getInstance() {
        if (that != null) {
            return that;
        }
        that = new NativeLibraryLoader();
        return that;
    }

    public <T extends Library> T load(String name, Class<T> interfaceClass) {
        return Native.load(name, interfaceClass);
    }
}
