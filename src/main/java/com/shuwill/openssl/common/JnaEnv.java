package com.shuwill.openssl.common;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.CommonNative;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.NativeLibraryLoader;
import com.shuwill.openssl.natives.X509Native;
import com.shuwill.openssl.natives.jna.Asn1JnaNative;
import com.shuwill.openssl.natives.jna.CommonJnaNative;
import com.shuwill.openssl.natives.jna.EvpJnaNative;
import com.shuwill.openssl.natives.jna.X509JnaNative;
import com.shuwill.openssl.natives.jna.impl.Asn1JnaNativeImpl;
import com.shuwill.openssl.natives.jna.impl.CommonJnaNativeImpl;
import com.shuwill.openssl.natives.jna.impl.EvpJnaNativeImpl;
import com.shuwill.openssl.natives.jna.impl.X509JnaNativeImpl;
import com.sun.jna.Library;

public class JnaEnv extends AbstractNativeEnv{

    private final String opensslLibrary;

    public JnaEnv(String opensslLibrary) {
        this.opensslLibrary = opensslLibrary;
    }

    private <T extends Library> T load(Class<T> classInterface) {
        final NativeLibraryLoader libraryLoader = NativeLibraryLoader.getInstance();
        return libraryLoader.load(opensslLibrary, classInterface);
    }

    @Override
    protected CommonNative createCommon() {
        return new CommonJnaNativeImpl(load(CommonJnaNative.class));
    }

    @Override
    protected ASN1Native createASN1() {
        return new Asn1JnaNativeImpl(load(Asn1JnaNative.class));
    }

    @Override
    protected EvpNative createEvp() {
        return new EvpJnaNativeImpl(load(EvpJnaNative.class));
    }

    @Override
    protected X509Native createX509() {
        return new X509JnaNativeImpl(load(X509JnaNative.class));
    }
}
