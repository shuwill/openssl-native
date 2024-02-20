package com.shuwill.openssl.key;

import com.shuwill.openssl.common.OpensslNativeEnvironment;
import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;

public class NativeEncodedKeyPairGenerator implements EncodedKeyPairGenerator {

    private final EncodedKeyPairGenerator that;

    private NativeEncodedKeyPairGenerator(EncodedKeyPairGenerator that) {
        this.that = that;
    }

    public static EncodedKeyPairGenerator getInstance(String algorithmName) {
        final OpensslNativeEnvironment opensslEnv = OpensslNativeEnvironment.get();
        if ("rsa".equalsIgnoreCase(algorithmName)) {
            return new NativeEncodedKeyPairGenerator(new RSAEncodedKeyPairGenerator(
                    opensslEnv.getNativeInterface(ASN1Native.class),
                    opensslEnv.getNativeInterface(EvpNative.class)
            ));
        } else if ("ec".equalsIgnoreCase(algorithmName)) {
            return new NativeEncodedKeyPairGenerator(new ECEncodedKeyPairGenerator(
                    opensslEnv.getNativeInterface(ASN1Native.class),
                    opensslEnv.getNativeInterface(EvpNative.class)
            ));
        } else {
            throw new IllegalArgumentException("not support algorithmName: " + algorithmName);
        }
    }

    @Override
    public void initialize(int keysize) {
        that.initialize(keysize);
    }

    @Override
    public void setCurveAlgorithm(String curveAlgorithm) {
        that.setCurveAlgorithm(curveAlgorithm);
    }

    @Override
    public EncodedKeyPair generateKeyPair() {
        return that.generateKeyPair();
    }

    @Override
    public void close() throws Exception {
        that.close();
    }
}
