package com.shuwill.openssl.crypto;

import com.shuwill.openssl.common.OpensslNativeEnvironment;
import com.shuwill.openssl.key.KeyParameter;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.Nativeable;
import com.shuwill.openssl.natives.pointer.EVP_CIPHER;
import com.shuwill.openssl.natives.pointer.EVP_CIPHER_CTX;
import com.shuwill.openssl.natives.pointer.EVP_MD;

import javax.crypto.Cipher;
import java.nio.IntBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

public class NativeCryptoCipher extends Nativeable implements CryptoCipher {

    static final int ENCRYPT_MODE = 1;
    static final int DECRYPT_MODE = 0;

    private final EvpNative evpNative;

    private final EVP_CIPHER_CTX evp_cipher_ctx;
    private final EVP_CIPHER evp_cipher;

    private NativeCryptoCipher(EvpNative evpNative, String algorithmName) {
        super(evpNative);
        this.evpNative = evpNative;
        this.evp_cipher_ctx = evpNative.throwOnError(
                evpNative::EVP_CIPHER_CTX_new,
                this,
                "init evp cipher error"
        );
        this.evp_cipher = evpNative.throwOnError(
                () -> evpNative.EVP_get_cipherbyname(algorithmName),
                this,
                String.format("not support algorithmName: %s", algorithmName)
        );
        this.evpNative.throwOnError(
                code -> code == 1,
                evpNative.EVP_CIPHER_is_a(this.evp_cipher, algorithmName),
                this,
                "not support algorithmName: " + algorithmName
        );
    }

    public static CryptoCipher getInstance(String algorithmName) {
        final EvpNative evpNative = OpensslNativeEnvironment.get().getNativeInterface(EvpNative.class);
        return new NativeCryptoCipher(evpNative, algorithmName);
    }

    @Override
    public CipherParameters generateParameters(byte[] data) {
        return this.generateParameters(null, data);
    }

    @Override
    public CipherParameters generateParameters(byte[] salt, byte[] data) {
        return this.generateParameters(salt, data, 1, "MD5");
    }

    @Override
    public CipherParameters generateParameters(byte[] salt, byte[] data, int count, String digestAlgorithmName) {
        byte[] key = new byte[evpNative.EVP_CIPHER_get_key_length(this.evp_cipher)];
        byte[] iv = new byte[EvpNative.EVP_MAX_IV_LENGTH];
        EVP_MD evp_md = evpNative.throwOnError(
                () -> evpNative.EVP_get_digestbyname(digestAlgorithmName),
                this,
                String.format("not support the digest name: %s", digestAlgorithmName)
        );
        final int keySize = evpNative.EVP_BytesToKey(
                this.evp_cipher,
                evp_md,
                salt,
                data,
                data.length,
                count,
                key,
                iv
        );
        this.evpNative.throwOnError(
                code -> code != 0,
                keySize,
                this,
                "generate cipher parameters error"
        );
        return new ParametersWithIV(new KeyParameter(key), iv);
    }

    @Override
    public void init(int mode, CipherParameters cipherParameters) throws InvalidAlgorithmParameterException {
        final int cipherMode = mode == Cipher.ENCRYPT_MODE ? ENCRYPT_MODE : DECRYPT_MODE;

        final byte[] key;
        byte[] iv = null;
        if (cipherParameters instanceof ParametersWithIV) {
            iv = ((ParametersWithIV) cipherParameters).getIV();
            final CipherParameters keyParameters = ((ParametersWithIV) cipherParameters).getParameters();
            if (!(keyParameters instanceof KeyParameter)) {
                throw new InvalidAlgorithmParameterException("Illegal parameters");
            }
            key = ((KeyParameter) keyParameters).getKey();
        } else if (cipherParameters instanceof KeyParameter) {
            key = ((KeyParameter) cipherParameters).getKey();
        } else {
            throw new InvalidAlgorithmParameterException("Illegal parameters");
        }

        this.evpNative.throwOnError(evpNative.EVP_CipherInit(
                this.evp_cipher_ctx,
                this.evp_cipher,
                key,
                iv,
                cipherMode
        ), this);
    }

    @Override
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return this.update(
                Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen),
                Arrays.copyOfRange(output, outputOffset, output.length)
        );
    }

    @Override
    public int update(byte[] input, byte[] output) {
        final IntBuffer outlengthBuffer = IntBuffer.allocate(1);
        this.evpNative.throwOnError(evpNative.EVP_CipherUpdate(
                this.evp_cipher_ctx,
                output,
                outlengthBuffer,
                input,
                input.length
        ), this);
        return outlengthBuffer.get();
    }

    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return this.doFinal(
                Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen),
                Arrays.copyOfRange(output, outputOffset, output.length)
        );
    }

    @Override
    public int doFinal(byte[] input, byte[] output) {
        final int updateLength = this.update(input, output);
        final IntBuffer outlengthBuffer = IntBuffer.allocate(1);
        this.evpNative.throwOnError(evpNative.EVP_CipherFinal_ex(
                this.evp_cipher_ctx,
                output,
                outlengthBuffer
        ), this);
        final int outlength = outlengthBuffer.get();
        return updateLength + outlength;
    }

}
