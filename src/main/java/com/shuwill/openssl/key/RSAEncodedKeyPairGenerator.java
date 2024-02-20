package com.shuwill.openssl.key;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.EVP_PKEY_CTX;

public class RSAEncodedKeyPairGenerator extends AbstractNativeEncodedKeyPairGenerator {

    private int keysize = 2048;

    RSAEncodedKeyPairGenerator(ASN1Native asn1Native, EvpNative evpNative) {
        super(asn1Native, evpNative);
    }

    public EVP_PKEY generateEVP_PKEY() {
        final int nid = asn1Native.OBJ_txt2nid("rsaEncryption");
        EVP_PKEY_CTX ctx = evpNative.throwOnError(() -> evpNative.EVP_PKEY_CTX_new_id(nid), this);
        evpNative.throwOnError(evpNative.EVP_PKEY_keygen_init(ctx), this);

        evpNative.throwOnError(evpNative.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize), this);

        final EVP_PKEY evp_pkey = evpNative.throwOnError(evpNative::EVP_PKEY_new, this);
        evpNative.throwOnError(evpNative.EVP_PKEY_generate(ctx, evp_pkey), this);
        return evp_pkey;
    }

    @Override
    public void initialize(int keysize) {
        this.keysize = keysize;
    }
}
