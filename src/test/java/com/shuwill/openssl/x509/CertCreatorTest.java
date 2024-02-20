package com.shuwill.openssl.x509;

import com.shuwill.openssl.pem.Pem;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;

public class CertCreatorTest extends X509AbstractTest{

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Test
    public void testCreateCert() throws Exception{
        try (final InputStream csrIn = Files.newInputStream(Paths.get(CRS_NAME))) {
            final byte[] csr = Pem.read(csrIn);

            try (X509Req x509Req = NativeX509Req.builder().encoded(csr).build()) {
                x509Req.parse();
                logger.info("x509 req subject:{}", x509Req.getSubject());

                try (final InputStream rootCertIn = Files.newInputStream(Paths.get(ROOT_CA_NAME));
                     final InputStream rootPrivateKeyIn = Files.newInputStream(Paths.get(ROOT_CA_PRIVATE_PEM_NAME));
                     X509 rootCa = NativeX509.builder().pem(rootCertIn).build()) {

                    rootCa.parse();

                    final Calendar notBefore = Calendar.getInstance();
                    final Calendar notAfter = Calendar.getInstance();
                    notAfter.setTime(notBefore.getTime());
                    notAfter.add(Calendar.YEAR, 2);

                    final EncryptedPrivateKeyInfo encryptedPrivatekey = new EncryptedPrivateKeyInfo(Pem.read(rootPrivateKeyIn));
                    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
                    SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(encryptedPrivatekey.getAlgName(), new BouncyCastleProvider());
                    PKCS8EncodedKeySpec rootCaPrivkey = encryptedPrivatekey.getKeySpec(pbeKeyFactory.generateSecret(keySpec));

                    try (X509 x509 = NativeX509.builder().version(2)
                            .serialNumber(System.currentTimeMillis())
                            .notBefore(notBefore)
                            .notAfter(notAfter)
                            .subject(x509Req.getSubject())
                            .issuer(rootCa.getIssuer())
                            .basicConstraints(BasicConstraints.builder().critical().ca().build())
                            .keyUsage(KeyUsage.builder().critical().nonRepudiation().digitalSignature().keyEncipherment().build())
                            .subjectKeyIdentifier(
                                    SubjectKeyIdentifier.builder()
                                            .hash()
                                            .context(ExtensionContext.builder().subjectCert(rootCa).build())
                                            .build()
                            )
                            .authorityKeyIdentifier(
                                    AuthorityKeyIdentifier.builder()
                                            .keyid()
                                            .issuer()
                                            .context(ExtensionContext.builder().issuerCert(rootCa).build())
                                            .build()
                            )
                            .publickey(x509Req.getPublickey())
                            .signPrivatekey(rootCaPrivkey)
                            .digestAlgorithm(DEFAULT_DIGEST_ALG)
                            .publicKeyAlgorithm(defaultPublicKeyAlgorithm)
                            .build();
                         final OutputStream out = Files.newOutputStream(Paths.get("openssl-created.crt"))
                    ) {

                        Pem.write(out, Pem.PEM_STRING_X509, x509.encode());
                    }
                }
            }
        }
    }
}
