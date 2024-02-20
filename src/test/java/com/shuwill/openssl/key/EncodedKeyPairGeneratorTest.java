package com.shuwill.openssl.key;

import com.shuwill.openssl.common.AbstractTest;
import com.shuwill.openssl.common.OpensslNativeEnvironment;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class EncodedKeyPairGeneratorTest extends AbstractTest {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Before
    public void initEnv() throws IOException {
        OpensslNativeEnvironment.init().useJni(getLibrary(NAITVE_LIBRARY_NAME), getLibrary(CRYPTO_LIBRARY_NAME));
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testEncodedKeyPairGenerator() throws Exception {
        final String algorithmName = "ec";
        try (EncodedKeyPairGenerator keyPairGenerator = NativeEncodedKeyPairGenerator.getInstance(algorithmName)) {
            final EncodedKeyPair encodedKeyPair = keyPairGenerator.generateKeyPair();

            KeyFactory keyFactory = KeyFactory.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
            final PrivateKey privateKey = keyFactory.generatePrivate(encodedKeyPair.getPrivatekey());
            logger.info("\n{}", privateKey);

            final PublicKey publicKey = keyFactory.generatePublic(encodedKeyPair.getPublickey());
            logger.info("\n{}", publicKey);
        }
    }

}
