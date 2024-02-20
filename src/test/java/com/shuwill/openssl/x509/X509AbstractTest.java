package com.shuwill.openssl.x509;

import com.shuwill.openssl.common.AbstractTest;
import com.shuwill.openssl.common.OpensslNativeEnvironment;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;

import java.io.IOException;
import java.security.Security;

public class X509AbstractTest extends AbstractTest {

    protected static final String ROOT_CA_NAME = "openssl-root-ca.crt";
    protected static final String ROOT_CA_PRIVATE_PEM_NAME = "openssl-root-ca.pem";
    protected static final String CRS_NAME = "openssl-created.csr";

    protected static final String DEFAULT_ENCRYPT_ALG = "rsa";
    protected static final String DEFAULT_DIGEST_ALG = "sha256";

    protected String defaultPublicKeyAlgorithm;
    protected final String password = "123";

    @Before
    public void initEnv() throws IOException {
        OpensslNativeEnvironment.init().useJni(getLibrary(NAITVE_LIBRARY_NAME), getLibrary(CRYPTO_LIBRARY_NAME));
        defaultPublicKeyAlgorithm = "ec".equals(DEFAULT_ENCRYPT_ALG) ? "id-ecPublicKey" : null;
        Security.addProvider(new BouncyCastleProvider());
    }
}
