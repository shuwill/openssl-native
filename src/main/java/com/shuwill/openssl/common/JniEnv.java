package com.shuwill.openssl.common;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.CommonNative;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.X509Native;
import com.shuwill.openssl.natives.jni.impl.Asn1JniNativeImpl;
import com.shuwill.openssl.natives.jni.impl.CommonJniNativeImpl;
import com.shuwill.openssl.natives.jni.impl.EvpJniNativeImpl;
import com.shuwill.openssl.natives.jni.impl.X509JniNativeImpl;

import java.util.concurrent.atomic.AtomicBoolean;

public class JniEnv extends AbstractNativeEnv{

    private static final AtomicBoolean JNI_LIBRARY_LOADED = new AtomicBoolean(false);

    private final String accessLibrary;
    private final String opensslLibrary;

    public JniEnv(String accessLibrary, String opensslLibrary) {
        this.accessLibrary = accessLibrary;
        this.opensslLibrary = opensslLibrary;
    }

    private void load() {
        if(!JNI_LIBRARY_LOADED.get()) {
            System.load(accessLibrary);
            System.load(opensslLibrary);
            JNI_LIBRARY_LOADED.compareAndSet(false, true);
        }
    }

    @Override
    protected CommonNative createCommon() {
        load();
        return new CommonJniNativeImpl();
    }

    @Override
    protected ASN1Native createASN1() {
        load();
        return new Asn1JniNativeImpl();
    }

    @Override
    protected EvpNative createEvp() {
        load();
        return new EvpJniNativeImpl();
    }

    @Override
    protected X509Native createX509() {
        load();
        return new X509JniNativeImpl();
    }
}
