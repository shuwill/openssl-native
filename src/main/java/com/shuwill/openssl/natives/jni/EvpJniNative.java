package com.shuwill.openssl.natives.jni;

import java.nio.ByteBuffer;

public class EvpJniNative {

    public static native long evpMdCtxNew();

    public static native void evpMdCtxReset(long Ctx);

    public static native void evpMdCtxFree(long Ctx);

    public static native long evpGetDigestByName(String name);

    public static native long evpGetDigestByNid(int type);

    public static native long evpGetDigestByObj(long o);

    public static native void evpMdFree(long Md);

    public static native String evpMdGetName(long Md);

    public static native String evpMdGetDescription(long Md);

    public static native int evpMdGetSize(long Md);

    public static native int evpMdCtxGetSize(long Md);

    public static native int evpDigestInit(long Ctx, long Md);

    public static native int evpDigestUpdate(long Ctx, ByteBuffer d, int cnt);

    public static native int evpDigestFinal(long Ctx, ByteBuffer Md, NativeInt s);

    public static native long evpCipherCtxNew();

    public static native int evpCipherCtxReset(long Ctx);

    public static native void evpCipherCtxFree(long Ctx);

    public static native long evpGetCipherByName(String name);

    public static native long evpGetCipherByNid(int type);

    public static native long evpGetCipherByObj(long a);

    public static native void evpCipherFree(long Cipher);

    public static native String evpCipherGetName(long Cipher);

    public static native String evpCipherGetDescription(long Cipher);

    public static native int evpCipherGetBlocksize(long Cipher);

    public static native int evpCipherGetMode(long Cipher);

    public static native int evpCipherIs(long Cipher, String name);

    public static native int evpCipherGetKeyLength(long Cipher);

    public static native int evpCipherCtxGetKeyLength(long Ctx);

    public static native int evpCipherCtxSetKeyLength(long Ctx, int keylen);

    public static native int evpCipherCtxSetPadding(long Ctx, int pad);

    public static native int evpCipherGetIvLength(long Cipher);

    public static native int evpCipherCtxGetIvLength(long Ctx);

    public static native int evpBytesToKey(long type, long evpMd, ByteBuffer salt, ByteBuffer data, int datal, int count, ByteBuffer key, ByteBuffer iv);

    public static native int evpCipherInit(long Ctx, long Cipher, ByteBuffer key, ByteBuffer iv, int enc);

    public static native int evpCipherUpdate(long Ctx, ByteBuffer out, NativeInt outl, ByteBuffer in, int inl);

    public static native int evpCipherFinal(long Ctx, ByteBuffer out, NativeInt outl);

    public static native long evpPkeyCtxNewId(int id, long e);

    public static native long evpPkeyCtxNew(long pkey, long e);

    public static native void evpPkeyCtxFree(long Ctx);

    public static native long evpPkeyNew();

    public static native void evpPkeyFree(long key);

    public static native int evpPkeyCtxIs(long Ctx, String keytype);

    public static native int evpPkeyKeygenInit(long Ctx);

    public static native int evpPkeyParamgenInit(long Ctx);

    public static native int evpPkeyGenerate(long Ctx, long pPkey);

    public static native int evpPkeyParamgen(long Ctx, long pPkey);

    public static native int evpPkeyKeygen(long Ctx, long pPkey);

    public static native int evpPkeyCtxSetRsaKeygenBits(long Ctx, int mbits);

    public static native int evpPkeyCtxSetEcParamgenCurveNid(long Ctx, int nid);

    public static native int evpPkeyCtxSetEcParamenc(long Ctx, int paramenc);

    public static native long evpPkey2Pkcs8(long Pkey);

    public static native int i2dPkcs8PrivkeyInfoBio(long bp, long p8inf);

    public static native long d2iPkcs8PrivkeyInfoBio(long bp);

    public static native long evpPkcs82Pkey(long p8);

    public static native void pkcs8PrivkeyInfoFree(long p8);

    public static native int i2dPubkeyBio(long bp, long Pkey);

    public static native long d2iPubkeyBio(long bp);

    public static native long X509GetPubkey(long x);

    public static native long X509ReqGetPubkey(long req);

    public static native int PEMWriteBioPKCS8PrivateKey(long bp, long pkey, long cipher, ByteBuffer pwd);

    public static native int i2dPKCS8PrivateKeyNidBio(long bp, long pkey, int nid, ByteBuffer pwd);
}
