package com.shuwill.openssl.key;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.Nativeable;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.PKCS8_PRIV_KEY_INFO;

import java.nio.IntBuffer;

public abstract class AbstractNativeEncodedKeyPairGenerator extends Nativeable implements EncodedKeyPairGenerator {

    private static final int KEY_BUFFER_SIZE = 8192;

    protected final ASN1Native asn1Native;
    protected final EvpNative evpNative;

    private EVP_PKEY evp_pkey;

    protected AbstractNativeEncodedKeyPairGenerator(ASN1Native asn1Native, EvpNative evpNative) {
        super(asn1Native);
        this.asn1Native = asn1Native;
        this.evpNative = evpNative;
    }

    @Override
    public EncodedKeyPair generateKeyPair() {
        this.evp_pkey = this.generateEVP_PKEY();
        return new NaitveEncodedKeyPair(
                this.evp_pkey,
                this.asn1Native,
                this.evpNative,
                this.getPrivateKey(), this.getPublicKey()
        );
    }

    private byte[] getPrivateKey() {
        BIO bio = this.createBIO();
        PKCS8_PRIV_KEY_INFO pkcs8_priv_key_info = evpNative.throwOnError(
                () -> evpNative.EVP_PKEY2PKCS8(evp_pkey),
                this
        );
        this.evpNative.throwOnError(evpNative.i2d_PKCS8_PRIV_KEY_INFO_bio(
                bio,
                pkcs8_priv_key_info
        ), this);

        return this.readBio(bio);
    }

    private byte[] getPublicKey() {
        BIO bio = this.createBIO();
        this.evpNative.throwOnError(evpNative.i2d_PUBKEY_bio(bio, evp_pkey), this);

        byte[] buffer = new byte[KEY_BUFFER_SIZE];
        final IntBuffer readbytes = IntBuffer.allocate(1);
        evpNative.BIO_read_ex(bio, buffer, buffer.length, readbytes);

        final int length = readbytes.get();
        byte[] publicKey = new byte[length];
        System.arraycopy(buffer, 0, publicKey, 0, length);
        return publicKey;
    }

    protected abstract EVP_PKEY generateEVP_PKEY();

    @Override
    public void initialize(int keysize) {

    }

    @Override
    public void setCurveAlgorithm(String curveAlgorithm) {

    }
}
