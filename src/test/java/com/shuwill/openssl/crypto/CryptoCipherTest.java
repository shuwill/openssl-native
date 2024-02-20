package com.shuwill.openssl.crypto;

import com.shuwill.openssl.common.AbstractTest;
import com.shuwill.openssl.common.OpensslNativeEnvironment;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.IOException;
import java.util.Base64;

public class CryptoCipherTest extends AbstractTest {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final int BUFFER_SIZE = 1024;

    @Before
    public void initTestEnv() throws IOException {
        OpensslNativeEnvironment.init().useJni(getLibrary(NAITVE_LIBRARY_NAME), getLibrary(CRYPTO_LIBRARY_NAME));
    }

    @Test
    public void testCipher() throws Exception {
        final String algorithmName = "aes-256-ecb";
        final String source = "source";
        final String key = "123";

        try (CryptoCipher encrypter = NativeCryptoCipher.getInstance(algorithmName)) {
            final CipherParameters encryptParameters = encrypter.generateParameters(key.getBytes());
            encrypter.init(Cipher.ENCRYPT_MODE, encryptParameters);

            final byte[] encryptBuffer = new byte[BUFFER_SIZE];
            final int encryptLength = encrypter.doFinal(source.getBytes(), encryptBuffer);

            byte[] encryptResult = new byte[encryptLength];
            System.arraycopy(encryptBuffer, 0, encryptResult, 0, encryptLength);
            logger.info("encrypt data: {}", Base64.getEncoder().encodeToString(encryptResult));

            try (CryptoCipher decrypter = NativeCryptoCipher.getInstance(algorithmName)) {
                final CipherParameters decryptParameters = decrypter.generateParameters(key.getBytes());
                decrypter.init(Cipher.DECRYPT_MODE, decryptParameters);

                final byte[] decryptBuffer = new byte[BUFFER_SIZE];
                final int decryptLength = decrypter.doFinal(encryptResult, decryptBuffer);

                byte[] decryptResult = new byte[decryptLength];
                System.arraycopy(decryptBuffer, 0, decryptResult, 0, decryptLength);
                logger.info("decrypt data: {}", new String(decryptResult));

                Assert.assertEquals(source, new String(decryptResult));
            }
        }
    }
}
