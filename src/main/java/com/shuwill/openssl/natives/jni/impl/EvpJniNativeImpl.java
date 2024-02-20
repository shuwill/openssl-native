package com.shuwill.openssl.natives.jni.impl;


import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.jni.EvpJniNative;
import com.shuwill.openssl.natives.jni.NativeInt;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.EVP_CIPHER;
import com.shuwill.openssl.natives.pointer.EVP_CIPHER_CTX;
import com.shuwill.openssl.natives.pointer.EVP_MD;
import com.shuwill.openssl.natives.pointer.EVP_MD_CTX;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.EVP_PKEY_CTX;
import com.shuwill.openssl.natives.pointer.PKCS8_PRIV_KEY_INFO;
import com.shuwill.openssl.natives.pointer.X509;
import com.shuwill.openssl.natives.pointer.X509_REQ;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

public class EvpJniNativeImpl extends CommonJniNativeImpl implements EvpNative {

    @Override
    public EVP_MD_CTX EVP_MD_CTX_new() {
        return new EVP_MD_CTX(EvpJniNative.evpMdCtxNew(), this);
    }

    @Override
    public void EVP_MD_CTX_reset(EVP_MD_CTX ctx) {
        EvpJniNative.evpMdCtxReset(ctx.addr(Long.class));
    }

    @Override
    public void EVP_MD_CTX_free(EVP_MD_CTX ctx) {
        EvpJniNative.evpMdCtxFree(ctx.addr(Long.class));
    }

    @Override
    public EVP_MD EVP_get_digestbyname(String name) {
        return new EVP_MD(EvpJniNative.evpGetDigestByName(name), this);
    }

    @Override
    public EVP_MD EVP_get_digestbynid(int type) {
        return new EVP_MD(EvpJniNative.evpGetDigestByNid(type), this);
    }

    @Override
    public EVP_MD EVP_get_digestbyobj(ASN1_OBJECT o) {
        return new EVP_MD(EvpJniNative.evpGetDigestByObj(o.addr(Long.class)), this);
    }

    @Override
    public void EVP_MD_free(EVP_MD md) {
        EvpJniNative.evpMdFree(md.addr(Long.class));
    }

    @Override
    public String EVP_MD_get0_name(EVP_MD md) {
        return EvpJniNative.evpMdGetName(md.addr(Long.class));
    }

    @Override
    public String EVP_MD_get0_description(EVP_MD md) {
        return EvpJniNative.evpMdGetDescription(md.addr(Long.class));
    }

    @Override
    public int EVP_MD_get_size(EVP_MD md) {
        return EvpJniNative.evpMdGetSize(md.addr(Long.class));
    }

    @Override
    public int EVP_MD_CTX_get_size(EVP_MD_CTX md) {
        return EvpJniNative.evpMdCtxGetSize(md.addr(Long.class));
    }

    @Override
    public int EVP_DigestInit(EVP_MD_CTX ctx, EVP_MD md) {
        return EvpJniNative.evpDigestInit(ctx.addr(Long.class), md.addr(Long.class));
    }

    @Override
    public int EVP_DigestUpdate(EVP_MD_CTX ctx, byte[] d, int cnt) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(d.length);
        buffer.put(d);
        return EvpJniNative.evpDigestUpdate(ctx.addr(Long.class), buffer, cnt);
    }

    @Override
    public int EVP_DigestFinal_ex(EVP_MD_CTX ctx, byte[] md, IntBuffer s) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(md.length);
        NativeInt size = new NativeInt();
        final int result = EvpJniNative.evpDigestFinal(ctx.addr(Long.class), buffer, size);
        buffer.get(md);
        s.put(size.value());
        s.position(0);
        return result;
    }

    @Override
    public EVP_CIPHER_CTX EVP_CIPHER_CTX_new() {
        return new EVP_CIPHER_CTX(EvpJniNative.evpCipherCtxNew(), this);
    }

    @Override
    public int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX ctx) {
        return EvpJniNative.evpCipherCtxReset(ctx.addr(Long.class));
    }

    @Override
    public void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX ctx) {
        EvpJniNative.evpCipherCtxFree(ctx.addr(Long.class));
    }

    @Override
    public EVP_CIPHER EVP_get_cipherbyname(String name) {
        return new EVP_CIPHER(EvpJniNative.evpGetCipherByName(name), this);
    }

    @Override
    public EVP_CIPHER EVP_get_cipherbynid(int type) {
        return new EVP_CIPHER(EvpJniNative.evpGetCipherByNid(type), this);
    }

    @Override
    public EVP_CIPHER EVP_get_cipherbyobj(ASN1_OBJECT a) {
        return new EVP_CIPHER(EvpJniNative.evpGetCipherByObj(a.addr(Long.class)), this);
    }

    @Override
    public void EVP_CIPHER_free(EVP_CIPHER cipher) {
        EvpJniNative.evpCipherFree(cipher.addr(Long.class));
    }

    @Override
    public String EVP_CIPHER_get0_name(EVP_CIPHER cipher) {
        return EvpJniNative.evpCipherGetName(cipher.addr(Long.class));
    }

    @Override
    public String EVP_CIPHER_get0_description(EVP_CIPHER cipher) {
        return EvpJniNative.evpCipherGetDescription(cipher.addr(Long.class));
    }

    @Override
    public int EVP_CIPHER_get_block_size(EVP_CIPHER cipher) {
        return EvpJniNative.evpCipherGetBlocksize(cipher.addr(Long.class));
    }

    @Override
    public int EVP_CIPHER_get_mode(EVP_CIPHER cipher) {
        return EvpJniNative.evpCipherGetMode(cipher.addr(Long.class));
    }

    @Override
    public int EVP_CIPHER_is_a(EVP_CIPHER cipher, String name) {
        return EvpJniNative.evpCipherIs(cipher.addr(Long.class), name);
    }

    @Override
    public int EVP_CIPHER_get_key_length(EVP_CIPHER cipher) {
        return EvpJniNative.evpCipherGetKeyLength(cipher.addr(Long.class));
    }

    @Override
    public int EVP_CIPHER_CTX_get_key_length(EVP_CIPHER_CTX ctx) {
        return EvpJniNative.evpCipherCtxGetKeyLength(ctx.addr(Long.class));
    }

    @Override
    public int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX ctx, int keylen) {
        return EvpJniNative.evpCipherCtxSetKeyLength(ctx.addr(Long.class), keylen);
    }

    @Override
    public int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX ctx, int pad) {
        return EvpJniNative.evpCipherCtxSetPadding(ctx.addr(Long.class), pad);
    }

    @Override
    public int EVP_CIPHER_get_iv_length(EVP_CIPHER cipher) {
        return EvpJniNative.evpCipherGetIvLength(cipher.addr(Long.class));
    }

    @Override
    public int EVP_CIPHER_CTX_get_iv_length(EVP_CIPHER_CTX ctx) {
        return EvpJniNative.evpCipherCtxGetIvLength(ctx.addr(Long.class));
    }

    @Override
    public int EVP_BytesToKey(EVP_CIPHER type, EVP_MD evp_md, byte[] salt, byte[] data, int datal, int count, byte[] key, byte[] iv) {
        ByteBuffer saltbuffer = null;
        if (salt != null) {
            saltbuffer = ByteBuffer.allocateDirect(salt.length);
            saltbuffer.put(salt);
        }

        ByteBuffer databuffer = ByteBuffer.allocateDirect(data.length);
        databuffer.put(data);

        final ByteBuffer keybuffer = ByteBuffer.allocateDirect(key.length);
        final ByteBuffer ivbuffer = ByteBuffer.allocateDirect(iv.length);

        final int result = EvpJniNative.evpBytesToKey(type.addr(Long.class), evp_md.addr(Long.class), saltbuffer, databuffer, databuffer.capacity(), count, keybuffer, ivbuffer);
        keybuffer.get(key);
        ivbuffer.get(iv);
        return result;
    }

    @Override
    public int EVP_CipherInit(EVP_CIPHER_CTX ctx, EVP_CIPHER cipher, byte[] key, byte[] iv, int enc) {
        final ByteBuffer keybuffer = ByteBuffer.allocateDirect(key.length);
        keybuffer.put(key);

        final ByteBuffer ivbuffer = ByteBuffer.allocateDirect(iv.length);
        ivbuffer.put(iv);

        return EvpJniNative.evpCipherInit(ctx.addr(Long.class), cipher.addr(Long.class), keybuffer, ivbuffer, enc);
    }

    @Override
    public int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, byte[] out, IntBuffer outl, byte[] in, int inl) {
        ByteBuffer outbuffer = ByteBuffer.allocateDirect(out.length);
        ByteBuffer inbuffer = ByteBuffer.allocateDirect(in.length);
        inbuffer.put(in);
        NativeInt outlen = new NativeInt();
        final int result = EvpJniNative.evpCipherUpdate(ctx.addr(Long.class), outbuffer, outlen, inbuffer, inl);
        outbuffer.get(out);
        outl.put(outlen.value());
        outl.position(0);
        return result;
    }

    @Override
    public int EVP_CipherFinal_ex(EVP_CIPHER_CTX ctx, byte[] out, IntBuffer outl) {
        ByteBuffer outbuffer = ByteBuffer.allocateDirect(out.length);
        NativeInt outlen = new NativeInt();
        final int result = EvpJniNative.evpCipherFinal(ctx.addr(Long.class), outbuffer, outlen);
        outbuffer.get(out);
        outl.put(outlen.value());
        outl.position(0);
        return result;
    }

    @Override
    public EVP_PKEY_CTX EVP_PKEY_CTX_new_id(int id) {
        return new EVP_PKEY_CTX(EvpJniNative.evpPkeyCtxNewId(id, 0), this);
    }

    @Override
    public EVP_PKEY_CTX EVP_PKEY_CTX_new(EVP_PKEY pkey) {
        return new EVP_PKEY_CTX(EvpJniNative.evpPkeyCtxNew(pkey.addr(Long.class), 0), this);
    }

    @Override
    public void EVP_PKEY_CTX_free(EVP_PKEY_CTX ctx) {
        EvpJniNative.evpPkeyCtxFree(ctx.addr(Long.class));
    }

    @Override
    public EVP_PKEY EVP_PKEY_new() {
        return new EVP_PKEY(EvpJniNative.evpPkeyNew(), this);
    }

    @Override
    public void EVP_PKEY_free(EVP_PKEY key) {
        EvpJniNative.evpPkeyFree(key.addr(Long.class));
    }

    @Override
    public int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX ctx, String keytype) {
        return EvpJniNative.evpPkeyCtxIs(ctx.addr(Long.class), keytype);
    }

    @Override
    public int EVP_PKEY_keygen_init(EVP_PKEY_CTX ctx) {
        return EvpJniNative.evpPkeyKeygenInit(ctx.addr(Long.class));
    }

    @Override
    public int EVP_PKEY_paramgen_init(EVP_PKEY_CTX ctx) {
        return EvpJniNative.evpPkeyParamgenInit(ctx.addr(Long.class));
    }

    @Override
    public int EVP_PKEY_generate(EVP_PKEY_CTX ctx, EVP_PKEY pkey) {
        return EvpJniNative.evpPkeyGenerate(ctx.addr(Long.class), pkey.addr(Long.class));
    }

    @Override
    public int EVP_PKEY_paramgen(EVP_PKEY_CTX ctx, EVP_PKEY pkey) {
        return EvpJniNative.evpPkeyParamgen(ctx.addr(Long.class), pkey.addr(Long.class));
    }

    @Override
    public int EVP_PKEY_keygen(EVP_PKEY_CTX ctx, EVP_PKEY pkey) {
        return EvpJniNative.evpPkeyKeygen(ctx.addr(Long.class), pkey.addr(Long.class));
    }

    @Override
    public int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX ctx, int mbits) {
        return EvpJniNative.evpPkeyCtxSetRsaKeygenBits(ctx.addr(Long.class), mbits);
    }

    @Override
    public int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX ctx, int nid) {
        return EvpJniNative.evpPkeyCtxSetEcParamgenCurveNid(ctx.addr(Long.class), nid);
    }

    @Override
    public int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX ctx, int param_enc) {
        return EvpJniNative.evpPkeyCtxSetEcParamenc(ctx.addr(Long.class), param_enc);
    }

    @Override
    public PKCS8_PRIV_KEY_INFO EVP_PKEY2PKCS8(EVP_PKEY pkey) {
        return new PKCS8_PRIV_KEY_INFO(EvpJniNative.evpPkey2Pkcs8(pkey.addr(Long.class)), this);
    }

    @Override
    public int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO bp, PKCS8_PRIV_KEY_INFO p8inf) {
        return EvpJniNative.i2dPkcs8PrivkeyInfoBio(bp.addr(Long.class), p8inf.addr(Long.class));
    }

    @Override
    public PKCS8_PRIV_KEY_INFO d2i_PKCS8_PRIV_KEY_INFO_bio(BIO bp) {
        return new PKCS8_PRIV_KEY_INFO(EvpJniNative.d2iPkcs8PrivkeyInfoBio(bp.addr(Long.class)), this);
    }

    @Override
    public EVP_PKEY EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO p8) {
        return new EVP_PKEY(EvpJniNative.evpPkcs82Pkey(p8.addr(Long.class)), this);
    }

    @Override
    public void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO p8) {
        EvpJniNative.pkcs8PrivkeyInfoFree(p8.addr(Long.class));
    }

    @Override
    public int i2d_PUBKEY_bio(BIO bp, EVP_PKEY pkey) {
        return EvpJniNative.i2dPubkeyBio(bp.addr(Long.class), pkey.addr(Long.class));
    }

    @Override
    public EVP_PKEY d2i_PUBKEY_bio(BIO bp) {
        return new EVP_PKEY(EvpJniNative.d2iPubkeyBio(bp.addr(Long.class)), this);
    }

    @Override
    public EVP_PKEY X509_get_pubkey(X509 x) {
        return new EVP_PKEY(EvpJniNative.X509GetPubkey(x.addr(Long.class)), this);
    }

    @Override
    public EVP_PKEY X509_REQ_get_pubkey(X509_REQ req) {
        return new EVP_PKEY(EvpJniNative.X509ReqGetPubkey(req.addr(Long.class)), this);
    }

    @Override
    public int PEM_write_bio_PKCS8PrivateKey(BIO bp, EVP_PKEY pkey, EVP_CIPHER cipher, byte[] pwd) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(pwd.length);
        buffer.put(pwd);
        return EvpJniNative.PEMWriteBioPKCS8PrivateKey(
                bp.addr(Long.class),
                pkey.addr(Long.class),
                cipher.addr(Long.class),
                buffer
        );
    }

    @Override
    public int i2d_PKCS8PrivateKey_nid_bio(BIO bp, EVP_PKEY pkey, int nid, byte[] pwd) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(pwd.length);
        buffer.put(pwd);
        return EvpJniNative.i2dPKCS8PrivateKeyNidBio(
                bp.addr(Long.class),
                pkey.addr(Long.class),
                nid,
                buffer
        );
    }
}
