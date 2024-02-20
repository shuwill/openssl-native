package com.shuwill.openssl.natives;

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

import java.nio.IntBuffer;

/**
 * @author shuwei.wang
 * @description:
 */
public interface EvpNative extends CommonNative {

    /* longest known is SHA512 */
    int EVP_MAX_MD_SIZE = 64;
    int EVP_MAX_KEY_LENGTH = 64;
    int EVP_MAX_IV_LENGTH = 16;
    int EVP_MAX_BLOCK_LENGTH = 32;

    /* Modes for ciphers */
    int EVP_CIPH_STREAM_CIPHER = 0x0;
    int EVP_CIPH_ECB_MODE = 0x1;
    int EVP_CIPH_CBC_MODE = 0x2;
    int EVP_CIPH_CFB_MODE = 0x3;
    int EVP_CIPH_OFB_MODE = 0x4;
    int EVP_CIPH_CTR_MODE = 0x5;
    int EVP_CIPH_GCM_MODE = 0x6;
    int EVP_CIPH_CCM_MODE = 0x7;
    int EVP_CIPH_XTS_MODE = 0x10001;
    int EVP_CIPH_WRAP_MODE = 0x10002;
    int EVP_CIPH_OCB_MODE = 0x10003;
    int EVP_CIPH_SIV_MODE = 0x10004;
    int EVP_CIPH_GCM_SIV_MODE = 0x10005;
    int EVP_CIPH_MODE = 0xF0007;

    /* Values for EVP_PKEY_CTX_set_ec_param_enc() */
    int OPENSSL_EC_EXPLICIT_CURVE = 0x000;
    int OPENSSL_EC_NAMED_CURVE = 0x001;

    /**
     * Allocates and returns a digest context.
     *
     * @return
     */
    EVP_MD_CTX EVP_MD_CTX_new();

    /**
     * Resets the digest context ctx. This can be used to reuse an already existing context.
     *
     * @param ctx
     */
    void EVP_MD_CTX_reset(EVP_MD_CTX ctx);

    /**
     * Cleans up digest context ctx and frees up the space allocated to it.
     *
     * @param ctx
     */
    void EVP_MD_CTX_free(EVP_MD_CTX ctx);

    /**
     * Returns an EVP_MD structure when passed a digest name, a digest NID or an ASN1_OBJECT structure respectively.
     *
     * @param name
     * @return
     */
    EVP_MD EVP_get_digestbyname(String name);

    EVP_MD EVP_get_digestbynid(int type);

    EVP_MD EVP_get_digestbyobj(ASN1_OBJECT o);

    /**
     * Decrements the reference count for the fetched EVP_MD structure.
     * If the reference count drops to 0 then the structure is freed.
     *
     * @param md
     */
    void EVP_MD_free(EVP_MD md);

    /**
     * Return the name of the given message digest.
     *
     * @param md
     * @return
     */
    String EVP_MD_get0_name(EVP_MD md);

    /**
     * Returns a description of the digest, meant for display and human consumption.
     * The description is at the discretion of the digest implementation.
     *
     * @param md
     * @return
     */
    String EVP_MD_get0_description(EVP_MD md);

    /**
     * Return the size of the message digest when passed an EVP_MD or an EVP_MD_CTX structure, i.e. the size of the hash.
     *
     * @param md
     * @return
     */
    int EVP_MD_get_size(EVP_MD md);

    int EVP_MD_CTX_get_size(EVP_MD_CTX ctx);

    /**
     * Sets up digest context ctx to use a digest type
     *
     * @param ctx
     * @param md
     * @return
     */
    int EVP_DigestInit(EVP_MD_CTX ctx, EVP_MD md);

    /**
     * Hashes cnt bytes of data at d into the digest context ctx.
     * This function can be called several times on the same ctx to hash additional data.
     *
     * @param ctx
     * @param d
     * @param cnt
     * @return
     */
    int EVP_DigestUpdate(EVP_MD_CTX ctx, byte[] d, int cnt);

    /**
     * Retrieves the digest value from ctx and places it in md.
     * If the s parameter is not NULL then the number of bytes of data written (i.e. the length of the digest) will be written to the integer at s,
     * at most {@link EVP_MAX_MD_SIZE} bytes will be written unless the digest implementation allows changing the digest size, and it is set to a larger value by the application.
     * After calling EVP_DigestFinal_ex() no additional calls to {@link #EVP_DigestUpdate(EVP_MD_CTX, ByteBuffer, NativeLong)} can be made,
     * but {@link #EVP_DigestInit(EVP_MD_CTX, EVP_MD)} can be called to initialize a new digest operation.
     *
     * @param ctx
     * @param md
     * @param s
     * @return
     */
    int EVP_DigestFinal_ex(EVP_MD_CTX ctx, byte[] md, IntBuffer s);

    /**
     * Allocates and returns a cipher context.
     *
     * @return
     */
    EVP_CIPHER_CTX EVP_CIPHER_CTX_new();

    /**
     * Clears all information from a cipher context and free up any allocated memory associated with it, except the ctx itself.
     * This function should be called anytime ctx is reused by another EVP_CipherInit() / EVP_CipherUpdate() / EVP_CipherFinal() series of calls.
     *
     * @param ctx
     * @return
     */
    int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX ctx);

    /**
     * Clears all information from a cipher context and frees any allocated memory associated with it, including ctx itself.
     * This function should be called after all operations using a cipher are complete so sensitive information does not remain in memory.
     *
     * @param ctx
     */
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX ctx);

    /**
     * Returns an EVP_CIPHER structure when passed a cipher name, a cipher NID or an ASN1_OBJECT structure respectively.
     *
     * @param name
     * @return
     */
    EVP_CIPHER EVP_get_cipherbyname(String name);

    EVP_CIPHER EVP_get_cipherbynid(int type);

    EVP_CIPHER EVP_get_cipherbyobj(ASN1_OBJECT a);

    /**
     * Decrements the reference count for the fetched EVP_CIPHER structure. If the reference count drops to 0 then the structure is freed.
     *
     * @param cipher
     */
    void EVP_CIPHER_free(EVP_CIPHER cipher);

    /**
     * Return the name of the passed cipher or context.
     *
     * @param cipher
     * @return
     */
    String EVP_CIPHER_get0_name(EVP_CIPHER cipher);

    /**
     * Returns a description of the cipher, meant for display and human consumption. The description is at the discretion of the cipher implementation.
     *
     * @param cipher
     * @return
     */
    String EVP_CIPHER_get0_description(EVP_CIPHER cipher);

    /**
     * Return the block size of a cipher when passed an EVP_CIPHER or EVP_CIPHER_CTX structure.
     * The constant EVP_MAX_BLOCK_LENGTH is also the maximum block length for all ciphers.
     *
     * @param cipher
     * @return
     */
    int EVP_CIPHER_get_block_size(EVP_CIPHER cipher);

    /**
     * Return the block cipher mode:
     * EVP_CIPH_ECB_MODE, EVP_CIPH_CBC_MODE, EVP_CIPH_CFB_MODE, EVP_CIPH_OFB_MODE, EVP_CIPH_CTR_MODE,
     * EVP_CIPH_GCM_MODE, EVP_CIPH_CCM_MODE, EVP_CIPH_XTS_MODE, EVP_CIPH_WRAP_MODE, EVP_CIPH_OCB_MODE
     * or EVP_CIPH_SIV_MODE.
     * If the cipher is a stream cipher then EVP_CIPH_STREAM_CIPHER is returned.
     *
     * @param cipher
     * @return
     */
    int EVP_CIPHER_get_mode(EVP_CIPHER cipher);

    /**
     * Returns 1 if cipher is an implementation of an algorithm that's identifiable with name, otherwise 0.
     *
     * @param cipher
     * @param name
     * @return
     */
    int EVP_CIPHER_is_a(EVP_CIPHER cipher, String name);

    /**
     * Return the key length of a cipher when passed an EVP_CIPHER or EVP_CIPHER_CTX structure.
     * The constant {@link EVP_MAX_KEY_LENGTH} is the maximum key length for all ciphers.
     * Note: although EVP_CIPHER_get_key_length() is fixed for a given cipher,
     * the value of {@link #EVP_CIPHER_CTX_get_key_length(EVP_CIPHER_CTX)} may be different for variable key length ciphers.
     *
     * @param cipher
     * @return
     */
    int EVP_CIPHER_get_key_length(EVP_CIPHER cipher);

    int EVP_CIPHER_CTX_get_key_length(EVP_CIPHER_CTX ctx);

    /**
     * Sets the key length of the cipher context.
     * If the cipher is a fixed length cipher then attempting to set the key length to any value other than the fixed value is an error.
     *
     * @param ctx
     * @param keylen
     * @return
     */
    int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX ctx, int keylen);

    /**
     * Enables or disables padding.
     * This function should be called after the context is set up for encryption or decryption with EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or EVP_CipherInit_ex2().
     * By default, encryption operations are padded using standard block padding and the padding is checked and removed when decrypting.
     * If the pad parameter is zero then no padding is performed, the total amount of data encrypted or decrypted must then be a multiple of the block size or an error will occur.
     *
     * @param ctx
     * @param pad
     * @return
     */
    int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX ctx, int pad);

    /**
     * Return the IV length of a cipher when passed an EVP_CIPHER or EVP_CIPHER_CTX.
     * It will return zero if the cipher does not use an IV.
     * The constant {@link EVP_MAX_IV_LENGTH} is the maximum IV length for all ciphers.
     *
     * @param cipher
     * @return
     */
    int EVP_CIPHER_get_iv_length(EVP_CIPHER cipher);

    int EVP_CIPHER_CTX_get_iv_length(EVP_CIPHER_CTX ctx);

    /**
     * EVP_BytesToKey() derives a key and IV from various parameters.
     * type is the cipher to derive the key and IV for. md is the message digest to use.
     * The salt parameter is used as a salt in the derivation: it should point to an 8 byte buffer or NULL if no salt is used.
     * data is a buffer containing datal bytes which is used to derive the keying data.
     * count is the iteration count to use.
     * The derived key and IV will be written to key and iv respectively.
     *
     * @param type   the cipher to derive the key and IV for
     * @param evp_md the message digest to use
     * @param salt   The salt parameter is used as a salt in the derivation: it should point to an 8 byte buffer or NULL if no salt is used
     * @param data   data is a buffer containing datal bytes which is used to derive the keying data.
     * @param datal
     * @param count  the iteration count to use.
     * @param key
     * @param iv
     * @return
     */
    int EVP_BytesToKey(EVP_CIPHER type, EVP_MD evp_md, byte[] salt, byte[] data, int datal, int count, byte[] key, byte[] iv);

    /**
     * can be used for decryption or encryption.
     * The operation performed depends on the value of the enc parameter.
     * It should be set to 1 for encryption, 0 for decryption and -1 to leave the value unchanged (the actual value of ‘enc’ being supplied in a previous call).
     *
     * @param ctx
     * @param cipher
     * @param key
     * @param iv
     * @param enc
     * @return
     */
    int EVP_CipherInit(EVP_CIPHER_CTX ctx, EVP_CIPHER cipher, byte[] key, byte[] iv, int enc);

    int EVP_CipherUpdate(EVP_CIPHER_CTX ctx, byte[] out, IntBuffer outl, byte[] in, int inl);

    int EVP_CipherFinal_ex(EVP_CIPHER_CTX ctx, byte[] out, IntBuffer outl);

    /**
     * The EVP_PKEY_CTX_new_id() function allocates public key algorithm context using the key type specified by id.
     *
     * @param id
     * @param e
     * @return
     */
    EVP_PKEY_CTX EVP_PKEY_CTX_new_id(int id);

    /**
     * The EVP_PKEY_CTX_new() function allocates public key algorithm context using the pkey key type
     *
     * @param pkey
     * @param e
     * @return
     */
    EVP_PKEY_CTX EVP_PKEY_CTX_new(EVP_PKEY pkey);

    /**
     * frees up the context ctx. If ctx is NULL, nothing is done.
     *
     * @param ctx
     */
    void EVP_PKEY_CTX_free(EVP_PKEY_CTX ctx);

    /**
     * The EVP_PKEY_new() function allocates an empty EVP_PKEY structure
     * which is used by OpenSSL to store public and private keys.
     * The reference count is set to 1.
     *
     * @return
     */
    EVP_PKEY EVP_PKEY_new();


    /**
     * EVP_PKEY_free() decrements the reference count of key and, if the reference count is zero, frees it up.
     * If key is NULL, nothing is done.
     *
     * @param key
     */
    void EVP_PKEY_free(EVP_PKEY key);

    /**
     * frees up the context ctx. If ctx is NULL, nothing is done.
     *
     * @param ctx
     * @param keytype
     * @return
     */
    int EVP_PKEY_CTX_is_a(EVP_PKEY_CTX ctx, String keytype);

    /**
     * initializes a public key algorithm context ctx for a key generation operation.
     *
     * @param ctx
     * @return
     */
    int EVP_PKEY_keygen_init(EVP_PKEY_CTX ctx);

    /**
     * EVP_PKEY_paramgen_init() is similar to EVP_PKEY_keygen_init() except key parameters are generated.
     *
     * @param ctx
     * @return
     */
    int EVP_PKEY_paramgen_init(EVP_PKEY_CTX ctx);

    /**
     * EVP_PKEY_generate() performs the generation operation, the resulting key parameters or key are written to ppkey.
     * If ppkey is NULL when this function is called, it will be allocated,
     * and should be freed by the caller when no longer useful, using EVP_PKEY_free(3).
     *
     * @param ctx
     * @param pkey
     * @return
     */
    int EVP_PKEY_generate(EVP_PKEY_CTX ctx, EVP_PKEY pkey);

    /**
     * EVP_PKEY_paramgen() and EVP_PKEY_keygen() do exactly the same thing as EVP_PKEY_generate(),
     * after checking that the corresponding EVP_PKEY_paramgen_init() or EVP_PKEY_keygen_init() was used to initialize ctx.
     * These are older functions that are kept for backward compatibility. It is safe to use EVP_PKEY_generate() instead.
     *
     * @param ctx
     * @param pkey
     * @return
     */
    int EVP_PKEY_paramgen(EVP_PKEY_CTX ctx, EVP_PKEY pkey);

    int EVP_PKEY_keygen(EVP_PKEY_CTX ctx, EVP_PKEY pkey);

    int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX ctx, int mbits);

    /**
     * The EVP_PKEY_CTX_set_ec_paramgen_curve_nid() sets the EC curve for EC parameter generation to nid.
     * For EC parameter generation this macro must be called or an error occurs because there is no default curve.
     *
     * @param ctx
     * @param nid
     * @return
     */
    int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX ctx, int nid);

    int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX ctx, int param_enc);

    /**
     * The PKCS#8 functions encode
     *
     * @param a
     * @param pp
     * @return
     */
    PKCS8_PRIV_KEY_INFO EVP_PKEY2PKCS8(EVP_PKEY pkey);

    int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO bp, PKCS8_PRIV_KEY_INFO p8inf);

    PKCS8_PRIV_KEY_INFO d2i_PKCS8_PRIV_KEY_INFO_bio(BIO bp);

    EVP_PKEY EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO p8);

    void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO p8);

    /**
     * The X509 functions encode
     *
     * @param bp
     * @param pkey
     * @return
     */
    int i2d_PUBKEY_bio(BIO bp, EVP_PKEY pkey);

    EVP_PKEY d2i_PUBKEY_bio(BIO bp);

    EVP_PKEY X509_get_pubkey(X509 x);

    EVP_PKEY X509_REQ_get_pubkey(X509_REQ req);

    int PEM_write_bio_PKCS8PrivateKey(BIO bp, EVP_PKEY pkey, EVP_CIPHER cipher, byte[] pwd);

    int i2d_PKCS8PrivateKey_nid_bio(BIO bp, EVP_PKEY pkey, int nid, byte[] pwd);
}
