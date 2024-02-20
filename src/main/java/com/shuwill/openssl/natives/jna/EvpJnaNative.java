package com.shuwill.openssl.natives.jna;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

/**
 * @author shuwei.wang
 * @description:
 */
public interface EvpJnaNative extends CommonJnaNative {

    Pointer EVP_MD_CTX_new();

    void EVP_MD_CTX_reset(Pointer ctx);

    void EVP_MD_CTX_free(Pointer ctx);

    Pointer EVP_get_digestbyname(String name);

    Pointer EVP_get_digestbynid(int type);

    Pointer EVP_get_digestbyobj(Pointer o);

    void EVP_MD_free(Pointer md);

    String EVP_MD_get0_name(Pointer md);

    String EVP_MD_get0_description(Pointer md);

    int EVP_MD_get_size(Pointer md);

    int EVP_MD_CTX_get_size(Pointer ctx);

    int EVP_DigestInit(Pointer ctx, Pointer md);

    int EVP_DigestUpdate(Pointer ctx, ByteBuffer d, int cnt);

    int EVP_DigestFinal_ex(Pointer ctx, ByteBuffer md, IntBuffer s);

    Pointer EVP_CIPHER_CTX_new();

    int EVP_CIPHER_CTX_reset(Pointer ctx);

    void EVP_CIPHER_CTX_free(Pointer ctx);

    Pointer EVP_get_cipherbyname(String name);

    Pointer EVP_get_cipherbynid(int type);

    Pointer EVP_get_cipherbyobj(Pointer a);

    void EVP_CIPHER_free(Pointer cipher);

    String EVP_CIPHER_get0_name(Pointer cipher);

    String EVP_CIPHER_get0_description(Pointer cipher);

    int EVP_CIPHER_get_block_size(Pointer cipher);

    int EVP_CIPHER_get_mode(Pointer cipher);

    int EVP_CIPHER_is_a(Pointer cipher, String name);

    int EVP_CIPHER_get_key_length(Pointer cipher);

    int EVP_CIPHER_CTX_get_key_length(Pointer ctx);

    int EVP_CIPHER_CTX_set_key_length(Pointer ctx, int keylen);

    int EVP_CIPHER_CTX_set_padding(Pointer ctx, int pad);

    int EVP_CIPHER_get_iv_length(Pointer cipher);

    int EVP_CIPHER_CTX_get_iv_length(Pointer ctx);

    int EVP_BytesToKey(Pointer type, Pointer evp_md, byte[] salt, byte[] data, int datal, int count, ByteBuffer key, ByteBuffer iv);

    int EVP_CipherInit(Pointer ctx, Pointer cipher, byte[] key, byte[] iv, int enc);

    int EVP_CipherUpdate(Pointer ctx, ByteBuffer out, IntBuffer outl, ByteBuffer in, int inl);

    int EVP_CipherFinal_ex(Pointer ctx, ByteBuffer out, IntBuffer outl);

    Pointer EVP_PKEY_CTX_new_id(int id, Pointer e);

    Pointer EVP_PKEY_CTX_new(Pointer pkey, Pointer e);

    void EVP_PKEY_CTX_free(Pointer ctx);

    Pointer EVP_PKEY_new();

    void EVP_PKEY_free(Pointer key);

    int EVP_PKEY_CTX_is_a(Pointer ctx, String keytype);

    int EVP_PKEY_keygen_init(Pointer ctx);

    int EVP_PKEY_paramgen_init(Pointer ctx);

    int EVP_PKEY_generate(Pointer ctx, PointerByReference ppkey);

    int EVP_PKEY_paramgen(Pointer ctx, PointerByReference ppkey);

    int EVP_PKEY_keygen(Pointer ctx, PointerByReference ppkey);

    int EVP_PKEY_CTX_set_rsa_keygen_bits(Pointer ctx, int mbits);

    int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(Pointer ctx, int nid);

    int EVP_PKEY_CTX_set_ec_param_enc(Pointer ctx, int param_enc);

    Pointer EVP_PKEY2PKCS8(Pointer pkey);

    int i2d_PKCS8_PRIV_KEY_INFO_bio(Pointer bp, Pointer p8inf);

    Pointer d2i_PKCS8_PRIV_KEY_INFO_bio(Pointer bp, PointerByReference p8inf);

    Pointer EVP_PKCS82PKEY(Pointer p8);

    void PKCS8_PRIV_KEY_INFO_free(Pointer p8);

    int i2d_PUBKEY_bio(Pointer bp, Pointer pkey);

    Pointer d2i_PUBKEY_bio(Pointer bp, PointerByReference a);

    Pointer X509_get_pubkey(Pointer x);

    Pointer X509_REQ_get_pubkey(Pointer req);

    int PEM_write_bio_PKCS8PrivateKey(Pointer bp, Pointer pkey, Pointer cipher, Pointer kstr, int klen, Pointer cb, ByteBuffer pwd);

    int i2d_PKCS8PrivateKey_nid_bio(Pointer bp, Pointer x, int nid, Pointer kstr, int klen, Pointer cb, ByteBuffer u);
}
