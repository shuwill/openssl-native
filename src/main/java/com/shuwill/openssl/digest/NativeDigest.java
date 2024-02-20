package com.shuwill.openssl.digest;

import com.shuwill.openssl.common.OpensslNativeEnvironment;
import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.Nativeable;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;
import com.shuwill.openssl.natives.pointer.EVP_MD;
import com.shuwill.openssl.natives.pointer.EVP_MD_CTX;

import java.nio.IntBuffer;
import java.util.Arrays;

public class NativeDigest extends Nativeable implements Digest {

    private final EvpNative evpNative;

    private final EVP_MD_CTX evp_md_ctx;
    private final EVP_MD evp_md;

    private NativeDigest(ASN1Native asn1Native, EvpNative evpNative, String algorithmName, String oid) {
        super(asn1Native);
        this.evpNative = evpNative;
        this.evp_md_ctx = evpNative.throwOnError(
                evpNative::EVP_MD_CTX_new,
                this,
                "int evp md ctx error"
        );
        if(oid != null) {
            final ASN1_OBJECT md_oid = asn1Native.throwOnError(
                    () -> asn1Native.OBJ_txt2obj(oid, 1),
                    NativeDigest.this
            );
            final int nid = asn1Native.OBJ_obj2nid(md_oid);
            algorithmName = asn1Native.OBJ_nid2sn(nid);

        }
        String finalAlgorithmName = algorithmName;
        this.evp_md = evpNative.throwOnError(
                () -> evpNative.EVP_get_digestbyname(finalAlgorithmName),
                this,
                String.format("not support the digest name: %s", algorithmName)
        );
        this.evpNative.throwOnError(evpNative.EVP_DigestInit(this.evp_md_ctx, evp_md), this);
    }

    public static Digest getInstance(String algorithmName) {
        final OpensslNativeEnvironment opensslEnv = OpensslNativeEnvironment.get();
        return new NativeDigest(
                opensslEnv.getNativeInterface(ASN1Native.class),
                opensslEnv.getNativeInterface(EvpNative.class),
                algorithmName,
                null
        );
    }

    public static Digest getInstanceByOid(String oid) {
        final OpensslNativeEnvironment opensslEnv = OpensslNativeEnvironment.get();
        return new NativeDigest(
                opensslEnv.getNativeInterface(ASN1Native.class),
                opensslEnv.getNativeInterface(EvpNative.class),
                null,
                oid
        );
    }

    @Override
    public String getAlgorithmName() {
        return evpNative.EVP_MD_get0_name(this.evp_md);
    }

    @Override
    public int getDigestSize() {
        return evpNative.EVP_MD_get_size(this.evp_md);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        final byte[] data = Arrays.copyOfRange(in, inOff, inOff + len);
        this.evpNative.throwOnError(evpNative.EVP_DigestUpdate(
                this.evp_md_ctx,
                data,
                len
        ), this);
    }

    @Override
    public int doFinal(byte[] out) {
        final IntBuffer size = IntBuffer.allocate(1);
        this.evpNative.throwOnError(evpNative.EVP_DigestFinal_ex(
                evp_md_ctx,
                out,
                size
        ), this);
        return size.get();
    }

    @Override
    public void reset() {
        evpNative.EVP_MD_CTX_reset(this.evp_md_ctx);
    }
}
