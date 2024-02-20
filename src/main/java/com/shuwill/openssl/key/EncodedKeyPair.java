package com.shuwill.openssl.key;

import javax.crypto.EncryptedPrivateKeyInfo;
import java.io.IOException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author shuwei.wang
 * @description:
 */
public interface EncodedKeyPair {

    PKCS8EncodedKeySpec getPrivatekey();

    EncryptedPrivateKeyInfo getEncryptedPrivatekey(String algName, byte[] password) throws IOException;

    X509EncodedKeySpec getPublickey();
}
