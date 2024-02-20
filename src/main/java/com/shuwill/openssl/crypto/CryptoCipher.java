package com.shuwill.openssl.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * @author shuwei.wang
 * @description:
 */
public interface CryptoCipher extends AutoCloseable{

    CipherParameters generateParameters(byte[] data);

    /**
     *
     * @param salt
     * @param data
     * @return
     */
    CipherParameters generateParameters(byte[] salt, byte[] data);

    /** generate cipher parameters
     *
     * @param salt
     * @param data
     * @param dataLength
     * @param count
     * @param digestAlgorithmName
     * @return
     */
    CipherParameters generateParameters(byte[] salt, byte[] data, int count, String digestAlgorithmName);

    /**
     * Initializes the cipher with mode, key and iv.
     *
     * @param mode   {@link javax.crypto.Cipher#ENCRYPT_MODE} or
     *               {@link javax.crypto.Cipher#DECRYPT_MODE}
     * @param cipherParameters    cipherParameters
     * @throws InvalidKeyException                if the given key is inappropriate for
     *                                            initializing this cipher, or its keysize exceeds the maximum
     *                                            allowable keysize (as determined from the configured jurisdiction
     *                                            policy files).
     * @throws InvalidAlgorithmParameterException if the given algorithm
     *                                            parameters are inappropriate for this cipher, or this cipher
     *                                            requires algorithm parameters and {@code params} is {@code null}, or
     *                                            the given algorithm parameters imply a cryptographic strength
     *                                            that would exceed the legal limits (as determined from the
     *                                            configured jurisdiction policy files).
     */
    void init(int mode, CipherParameters cipherParameters) throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param input        the input byte array
     * @param inputOffset  the offset in input where the input starts
     * @param inputLen     the input length
     * @param output       the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException if there is insufficient space in the output
     *                              byte array
     */
    int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException;

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param input  the input array
     * @param output the output array
     * @return int number of bytes stored in {@code output}
     * @throws ShortBufferException if there is insufficient space in the output
     *                              buffer
     */
    int update(byte[] input, byte[] output) throws ShortBufferException;

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     *
     * @param input        the input byte array
     * @param inputOffset  the offset in input where the input starts
     * @param inputLen     the input length
     * @param output       the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException      if the given output byte array is too small
     *                                   to hold the result
     * @throws BadPaddingException       if this cipher is in decryption mode, and
     *                                   (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *                                   padding has been requested (only in encryption mode), and the
     *                                   total input length of the data processed by this cipher is not a
     *                                   multiple of block size; or if this encryption algorithm is unable
     *                                   to process the input data provided.
     */
    int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     *
     * @param input  the input array
     * @param output the output array
     * @return int number of bytes stored in {@code output}
     * @throws BadPaddingException       if this cipher is in decryption mode, and
     *                                   (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *                                   padding has been requested (only in encryption mode), and the
     *                                   total input length of the data processed by this cipher is not a
     *                                   multiple of block size; or if this encryption algorithm is unable
     *                                   to process the input data provided.
     * @throws ShortBufferException      if the given output buffer is too small to
     *                                   hold the result
     */
    int doFinal(byte[] input, byte[] output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
}
