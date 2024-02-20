package com.shuwill.openssl.x509;

import com.shuwill.openssl.key.EncodedKeyPair;
import com.shuwill.openssl.key.EncodedKeyPairGenerator;
import com.shuwill.openssl.key.NativeEncodedKeyPairGenerator;
import com.shuwill.openssl.pem.Pem;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.EncryptedPrivateKeyInfo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

public class RootCaCreatorTest extends X509AbstractTest{

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Test
    public void testCreateCaRoot() throws Exception {
        final Calendar notBefore = Calendar.getInstance();
        final Calendar notAfter = Calendar.getInstance();
        notAfter.setTime(notBefore.getTime());
        notAfter.add(Calendar.YEAR, 10);

        try (EncodedKeyPairGenerator keyPairGenerator = NativeEncodedKeyPairGenerator.getInstance(DEFAULT_ENCRYPT_ALG)) {
            final EncodedKeyPair keyPair = keyPairGenerator.generateKeyPair();

            try (X509 x509 = NativeX509.builder().version(2)
                    .serialNumber(System.currentTimeMillis())
                    .notBefore(notBefore)
                    .notAfter(notAfter)
                    .appendSubject(X509AttributeType.C, "CN")
                    .appendSubject(X509AttributeType.ST, "SH")
                    .appendSubject(X509AttributeType.O, "shuwill root CA organization")
                    .appendSubject(X509AttributeType.CN, "shuwill root CA")
                    .appendIssuer(X509AttributeType.C, "CN")
                    .appendIssuer(X509AttributeType.ST, "SH")
                    .appendIssuer(X509AttributeType.O, "shuwill root CA organization")
                    .appendIssuer(X509AttributeType.CN, "shuwill root CA")
                    .basicConstraints(BasicConstraints.builder().critical().ca().build())
                    .keyUsage(KeyUsage.builder().critical().keyCertSign().crlSign().build())
                    .subjectKeyIdentifier(
                            SubjectKeyIdentifier.builder()
                                    .hash()
                                    .context(ExtensionContext.builder().subjectSelf(true).build())
                                    .build()
                    )
                    .authorityKeyIdentifier(
                            AuthorityKeyIdentifier.builder()
                                    .keyid()
                                    .issuer()
                                    .context(ExtensionContext.builder().issuerSelf(true).build())
                                    .build()
                    )
                    .publickey(keyPair.getPublickey())
                    .signPrivatekey(keyPair.getPrivatekey())
                    .digestAlgorithm(DEFAULT_DIGEST_ALG)
                    .publicKeyAlgorithm(defaultPublicKeyAlgorithm)
                    .build()) {

                final byte[] encode = x509.encode();
                logger.info("\n{}", x509.print());

                ByteArrayOutputStream certOut = new ByteArrayOutputStream();
                Pem.write(certOut, Pem.PEM_STRING_X509, encode);

                logger.info("X509 cert:\n{}", certOut);

                Files.write(Paths.get(ROOT_CA_NAME), certOut.toByteArray());

                final String encryptAlg = "PBE-SHA1-3DES";
                final EncryptedPrivateKeyInfo encryptedPrivatekey = keyPair.getEncryptedPrivatekey(encryptAlg, password.getBytes());
                try (OutputStream caPrivatePem = Files.newOutputStream(Paths.get(ROOT_CA_PRIVATE_PEM_NAME))) {
                    Pem.write(caPrivatePem, Pem.PEM_STRING_PKCS8, encryptedPrivatekey.getEncoded());
                }

                final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
                final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certOut.toByteArray()));
                final Principal subjectDN = certificate.getSubjectDN();
                logger.info("subject dn: {}", subjectDN);

                final PublicKey publicKey = certificate.getPublicKey();
                logger.info("Public key:\n{}", publicKey);
            }
        }
    }

}
