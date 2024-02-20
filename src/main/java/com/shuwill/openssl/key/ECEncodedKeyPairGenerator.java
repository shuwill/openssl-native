package com.shuwill.openssl.key;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.EVP_PKEY_CTX;

public class ECEncodedKeyPairGenerator extends AbstractNativeEncodedKeyPairGenerator{

    private String curveAlgorithm = "sm2";

    ECEncodedKeyPairGenerator(ASN1Native asn1Native, EvpNative evpNative) {
        super(asn1Native, evpNative);
    }

    @Override
    protected EVP_PKEY generateEVP_PKEY() {
        final int nid = asn1Native.OBJ_txt2nid("id-ecPublicKey");
        EVP_PKEY_CTX param_ctx = evpNative.throwOnError(() -> evpNative.EVP_PKEY_CTX_new_id(nid), this);
        evpNative.throwOnError(evpNative.EVP_PKEY_paramgen_init(param_ctx), this);

        int curve_nid = asn1Native.OBJ_txt2nid(curveAlgorithm);
        evpNative.throwOnError(evpNative.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, curve_nid), this);
        evpNative.throwOnError(evpNative.EVP_PKEY_CTX_set_ec_param_enc(param_ctx, EvpNative.OPENSSL_EC_NAMED_CURVE), this);

        EVP_PKEY evp_pkey_param = evpNative.throwOnError(evpNative::EVP_PKEY_new, this);
        evpNative.throwOnError(evpNative.EVP_PKEY_paramgen(param_ctx, evp_pkey_param), this);

        EVP_PKEY_CTX key_ctx = evpNative.throwOnError(() -> evpNative.EVP_PKEY_CTX_new(evp_pkey_param), this);
        evpNative.throwOnError(evpNative.EVP_PKEY_keygen_init(key_ctx), this);

        final EVP_PKEY evp_pkey_pkey = evpNative.throwOnError(evpNative::EVP_PKEY_new, this);
        evpNative.throwOnError(evpNative.EVP_PKEY_keygen(key_ctx, evp_pkey_pkey),this);
        return evp_pkey_pkey;
    }

    public String getCurveAlgorithm() {
        return curveAlgorithm;
    }

    public void setCurveAlgorithm(String curveAlgorithm) {
        this.curveAlgorithm = curveAlgorithm;
    }
}
