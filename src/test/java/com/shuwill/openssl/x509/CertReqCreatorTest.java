package com.shuwill.openssl.x509;

import com.shuwill.openssl.key.EncodedKeyPair;
import com.shuwill.openssl.key.EncodedKeyPairGenerator;
import com.shuwill.openssl.key.NativeEncodedKeyPairGenerator;
import com.shuwill.openssl.pem.Pem;
import org.junit.Test;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CertReqCreatorTest extends X509AbstractTest {

    @Test
    public void testCreateCertReq() throws Exception {
        try (EncodedKeyPairGenerator keyPairGenerator = NativeEncodedKeyPairGenerator.getInstance(DEFAULT_ENCRYPT_ALG)) {
            final EncodedKeyPair keyPair = keyPairGenerator.generateKeyPair();

            try (X509Req req = NativeX509Req.builder()
                    .appendSubject(X509AttributeType.C, "CN")
                    .appendSubject(X509AttributeType.ST, "ShangHai")
                    .appendSubject(X509AttributeType.L, "SongJiang")
                    .appendSubject(X509AttributeType.O, "shuwill digital signature organization")
                    .appendSubject(X509AttributeType.CN, "shuwill digital signature")
                    .publickey(keyPair.getPublickey())
                    .privatekey(keyPair.getPrivatekey())
                    .digestAlgorithm(DEFAULT_DIGEST_ALG)
                    .build();
                 final OutputStream out = Files.newOutputStream(Paths.get(CRS_NAME))
            ) {

                Pem.write(out, Pem.PEM_STRING_X509_REQ, req.encode());
            }
        }
    }
}
