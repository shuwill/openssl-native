package com.shuwill.openssl.natives.jna.impl;

import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.jna.EvpJnaNative;
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
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

public class EvpJnaNativeImpl extends CommonJnaNativeImpl implements EvpNative {

    private final EvpJnaNative evpJnaNative;

    public EvpJnaNativeImpl(EvpJnaNative evpJnaNative) {
        super(evpJnaNative);
        this.evpJnaNative = evpJnaNative;
    }

    @Override
    public EVP_MD_CTX EVP_MD_CTX_new() {
        return new EVP_MD_CTX(evpJnaNative.EVP_MD_CTX_new(), this);
    }

    @Override
    public void EVP_MD_CTX_reset(EVP_MD_CTX ctx) {
        evpJnaNative.EVP_MD_CTX_reset(ctx.addr(Pointer.class));
    }

    @Override
    public void EVP_MD_CTX_free(EVP_MD_CTX ctx) {
        evpJnaNative.EVP_MD_CTX_free(ctx.addr(Pointer.class));
    }

    @Override
    public EVP_MD EVP_get_digestbyname(String name) {
        return new EVP_MD(evpJnaNative.EVP_get_digestbyname(name), this);
    }

    @Override
    public EVP_MD EVP_get_digestbynid(int type) {
        return new EVP_MD(evpJnaNative.EVP_get_digestbynid(type), this);
    }

    @Override
    public EVP_MD EVP_get_digestbyobj(ASN1_OBJECT o) {
        return new EVP_MD(evpJnaNative.EVP_get_digestbyobj(o.addr(Pointer.class)), this);
    }

    @Override
    public void EVP_MD_free(EVP_MD md) {
        evpJnaNative.EVP_MD_free(md.addr(Pointer.class));
    }

    @Override
    public String EVP_MD_get0_name(EVP_MD md) {
        return evpJnaNative.EVP_MD_get0_name(md.addr(Pointer.class));
    }

    @Override
    public String EVP_MD_get0_description(EVP_MD md) {
        return evpJnaNative.EVP_MD_get0_description(md.addr(Pointer.class));
    }

    @Override
    public int EVP_MD_get_size(EVP_MD md) {
        return evpJnaNative.EVP_MD_get_size(md.addr(Pointer.class));
    }

    @Override
    public int EVP_MD_CTX_get_size(EVP_MD_CTX ctx) {
        return evpJnaNative.EVP_MD_CTX_get_size(ctx.addr(Pointer.class));
    }

    @Override
    public int EVP_DigestInit(EVP_MD_CTX ctx, EVP_MD md) {
        return evpJnaNative.EVP_DigestInit(ctx.addr(Pointer.class), md.addr(Pointer.class));
    }

    @Override
    public int EVP_DigestUpdate(EVP_MD_CTX ctx, byte[] d, int cnt) {
        return evpJnaNative.EVP_DigestUpdate(ctx.addr(Pointer.class), ByteBuffer.wrap(d), cnt);
    }

    @Override
    public int EVP_DigestFinal_ex(EVP_MD_CTX ctx, byte[] md, IntBuffer s) {
        return evpJnaNative.EVP_DigestFinal_ex(ctx.addr(Pointer.class), ByteBuffer.wrap(md), s);
    }

    @Override
    public EVP_CIPHER_CTX EVP_CIPHER_CTX_new() {
        return new EVP_CIPHER_CTX(evpJnaNative.EVP_CIPHER_CTX_new(), this);
    }

    @Override
    public int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX ctx) {
        return evpJnaNative.EVP_CIPHER_CTX_reset(ctx.addr(Pointer.class));
    }

    @Override
    public void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX ctx) {
        evpJnaNative.EVP_CIPHER_CTX_free(ctx.addr(Pointer.class));
    }

    @Override
    public EVP_CIPHER EVP_get_cipherbyname(String name) {
        return new EVP_CIPHER(evpJnaNative.EVP_get_cipherbyname(name), this);
    }

    @Override
    public EVP_CIPHER EVP_get_cipherbynid(int type) {
        return new EVP_CIPHER(evpJnaNative.EVP_get_cipherbynid(type), this);
    }

    @Override
    public EVP_CIPHER EVP_get_cipherbyobj(ASN1_OBJECT a) {
        return new EVP_CIPHER(evpJnaNative.EVP_get_cipherbyobj(a.addr(Pointer.class)), this);
    }

    @Override
    public void EVP_CIPHER_free(EVP_CIPHER cipher) {
        evpJnaNative.EVP_CIPHER_free(cipher.addr(Pointer.class));
    }

    @Override
    public String EVP_CIPHER_get0_name(EVP_CIPHER cipher) {
        return evpJnaNative.EVP_CIPHER_get0_name(cipher.addr(Pointer.class));
    }

    @Override
    public String EVP_CIPHER_get0_description(EVP_CIPHER cipher) {
        return evpJnaNative.EVP_CIPHER_get0_description(cipher.addr(Pointer.class));
    }

    @Override
    public int EVP_CIPHER_get_block_size(EVP_CIPHER cipher) {
        return evpJnaNative.EVP_CIPHER_get_block_size(cipher.addr(Pointer.class));
    }

    @Override
    public int EVP_CIPHER_get_mode(EVP_CIPHER cipher) {
        return evpJnaNative.EVP_CIPHER_get_mode(cipher.addr(Pointer.class));
    }

    @Override
    public int EVP_CIPHER_is_a(EVP_CIPHER cipher, String name) {
        return evpJnaNative.EVP_CIPHER_is_a(cipher.addr(Pointer.class), name);
    }

    @Override
    public int EVP_CIPHER_get_key_length(EVP_CIPHER cipher) {
        return evpJnaNative.EVP_CIPHER_get_key_length(cipher.addr(Pointer.class));
    }

    @Override
    public int EVP_CIPHER_CTX_get_key_length(EVP_CIPHER_CTX ctx) {
        return evpJnaNative.EVP_CIPHER_CTX_get_key_length(ctx.addr(Pointer.class));
    }

    @Override
    public int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX ctx, int keylen) {
        return evpJnaNative.EVP_CIPHER_CTX_set_key_length(ctx.addr(Pointer.class), keylen);
    }

    @Override
    public int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX ctx, int pad) {
        return evpJnaNative.EVP_CIPHER_CTX_set_padding(ctx.addr(Pointer.class), pad);
    }

    @Override
    public int EVP_CIPHER_get_iv_length(EVP_CIPHER cipher) {
        return evpJnaNative.EVP_CIPHER_get_iv_length(cipher.addr(Pointer.class));
    }

    @Override
    public int EVP_CIPHER_CTX_get_iv_length(EVP_CIPHER_CTX ctx) {
        return evpJnaNative.EVP_CIPHER_CTX_get_iv_length(ctx.addr(Pointer.class));
    }

    @Override
    public int EVP_BytesToKey(EVP_CIPHER type, EVP_MD evp_md, byte[] salt, byte[] data, int datal, int count, byte[] key, byte[] iv) {
        return evpJnaNative.EVP_BytesToKey(type.addr(Pointer.class), evp_md.addr(Pointer.class), salt, data, datal, count, ByteBuffer.wrap(key), ByteBuffer.wrap(iv));
    }

    @Override
    public int EVP_CipherInit(EVP_CIPHER_CTX ctx, EVP_CIPHER cipher, byte[] key, byte[] iv, int enc) {
        return evpJnaNative.EVP_CipherInit(ctx.addr(Pointer.class), cipher.addr(Pointer.class), key, iv, enc);
    }

    @Override
    public int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, byte[] out, IntBuffer outl, byte[] in, int inl) {
        return evpJnaNative.EVP_CipherUpdate(ctx.addr(Pointer.class), ByteBuffer.wrap(out), outl, ByteBuffer.wrap(in), inl);
    }

    @Override
    public int EVP_CipherFinal_ex(EVP_CIPHER_CTX ctx, byte[] out, IntBuffer outl) {
        return evpJnaNative.EVP_CipherFinal_ex(ctx.addr(Pointer.class), ByteBuffer.wrap(out), outl);
    }

    @Override
    public EVP_PKEY_CTX EVP_PKEY_CTX_new_id(int id) {
        return new EVP_PKEY_CTX(evpJnaNative.EVP_PKEY_CTX_new_id(id, null), this);
    }

    @Override
    public EVP_PKEY_CTX EVP_PKEY_CTX_new(EVP_PKEY pkey) {
        return new EVP_PKEY_CTX(evpJnaNative.EVP_PKEY_CTX_new(pkey.addr(Pointer.class), null), this);
    }

    @Override
    public void EVP_PKEY_CTX_free(EVP_PKEY_CTX ctx) {
        evpJnaNative.EVP_PKEY_CTX_free(ctx.addr(Pointer.class));
    }

    @Override
    public EVP_PKEY EVP_PKEY_new() {
        return new EVP_PKEY(evpJnaNative.EVP_PKEY_new(), this);
    }

    @Override
    public void EVP_PKEY_free(EVP_PKEY key) {
        evpJnaNative.EVP_PKEY_free(key.addr(Pointer.class));
    }

    @Override
    public int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX ctx, String keytype) {
        return evpJnaNative.EVP_PKEY_CTX_is_a(ctx.addr(Pointer.class), keytype);
    }

    @Override
    public int EVP_PKEY_keygen_init(EVP_PKEY_CTX ctx) {
        return evpJnaNative.EVP_PKEY_keygen_init(ctx.addr(Pointer.class));
    }

    @Override
    public int EVP_PKEY_paramgen_init(EVP_PKEY_CTX ctx) {
        return evpJnaNative.EVP_PKEY_paramgen_init(ctx.addr(Pointer.class));
    }

    @Override
    public int EVP_PKEY_generate(EVP_PKEY_CTX ctx, EVP_PKEY pkey) {
        final Pointer evp_pkey = pkey.addr(Pointer.class);
        final PointerByReference p_evp_pkey = new PointerByReference(evp_pkey);
        return evpJnaNative.EVP_PKEY_generate(ctx.addr(Pointer.class), p_evp_pkey);
    }

    @Override
    public int EVP_PKEY_paramgen(EVP_PKEY_CTX ctx, EVP_PKEY pkey) {
        final Pointer evp_pkey = pkey.addr(Pointer.class);
        final PointerByReference p_evp_pkey = new PointerByReference(evp_pkey);
        return evpJnaNative.EVP_PKEY_paramgen(ctx.addr(Pointer.class), p_evp_pkey);
    }

    @Override
    public int EVP_PKEY_keygen(EVP_PKEY_CTX ctx, EVP_PKEY pkey) {
        final Pointer evp_pkey = pkey.addr(Pointer.class);
        final PointerByReference p_evp_pkey = new PointerByReference(evp_pkey);
        return evpJnaNative.EVP_PKEY_keygen(ctx.addr(Pointer.class), p_evp_pkey);
    }

    @Override
    public int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX ctx, int mbits) {
        return evpJnaNative.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.addr(Pointer.class), mbits);
    }

    @Override
    public int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX ctx, int nid) {
        return evpJnaNative.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.addr(Pointer.class), nid);
    }

    @Override
    public int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX ctx, int param_enc) {
        return evpJnaNative.EVP_PKEY_CTX_set_ec_param_enc(ctx.addr(Pointer.class), param_enc);
    }

    @Override
    public PKCS8_PRIV_KEY_INFO EVP_PKEY2PKCS8(EVP_PKEY pkey) {
        return new PKCS8_PRIV_KEY_INFO(evpJnaNative.EVP_PKEY2PKCS8(pkey.addr(Pointer.class)), this);
    }

    @Override
    public int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO bp, PKCS8_PRIV_KEY_INFO p8inf) {
        return evpJnaNative.i2d_PKCS8_PRIV_KEY_INFO_bio(bp.addr(Pointer.class), p8inf.addr(Pointer.class));
    }

    @Override
    public PKCS8_PRIV_KEY_INFO d2i_PKCS8_PRIV_KEY_INFO_bio(BIO bp) {
        return new PKCS8_PRIV_KEY_INFO(evpJnaNative.d2i_PKCS8_PRIV_KEY_INFO_bio(bp.addr(Pointer.class), null), this);
    }

    @Override
    public EVP_PKEY EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO p8) {
        return new EVP_PKEY(evpJnaNative.EVP_PKCS82PKEY(p8.addr(Pointer.class)), this);
    }

    @Override
    public void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO p8) {
        evpJnaNative.PKCS8_PRIV_KEY_INFO_free(p8.addr(Pointer.class));
    }

    @Override
    public int i2d_PUBKEY_bio(BIO bp, EVP_PKEY pkey) {
        return evpJnaNative.i2d_PUBKEY_bio(bp.addr(Pointer.class), pkey.addr(Pointer.class));
    }

    @Override
    public EVP_PKEY d2i_PUBKEY_bio(BIO bp) {
        return new EVP_PKEY(evpJnaNative.d2i_PUBKEY_bio(bp.addr(Pointer.class), null), this);
    }

    @Override
    public EVP_PKEY X509_REQ_get_pubkey(X509_REQ req) {
        return new EVP_PKEY(evpJnaNative.X509_REQ_get_pubkey(req.addr(Pointer.class)), this);
    }

    @Override
    public EVP_PKEY X509_get_pubkey(X509 x) {
        return new EVP_PKEY(evpJnaNative.X509_get_pubkey(x.addr(Pointer.class)), this);
    }

    @Override
    public int PEM_write_bio_PKCS8PrivateKey(BIO bp, EVP_PKEY pkey, EVP_CIPHER cipher, byte[] pwd) {
        return evpJnaNative.PEM_write_bio_PKCS8PrivateKey(
                bp.addr(Pointer.class),
                pkey.addr(Pointer.class),
                cipher.addr(Pointer.class),
                null,
                0,
                null,
                ByteBuffer.wrap(pwd)
        );
    }

    @Override
    public int i2d_PKCS8PrivateKey_nid_bio(BIO bp, EVP_PKEY pkey, int nid, byte[] pwd) {
        return evpJnaNative.i2d_PKCS8PrivateKey_nid_bio(
                bp.addr(Pointer.class),
                pkey.addr(Pointer.class),
                nid,
                null,
                0,
                null,
                ByteBuffer.wrap(pwd)
        );
    }
}
