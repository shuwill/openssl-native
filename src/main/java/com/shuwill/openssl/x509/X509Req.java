package com.shuwill.openssl.x509;

import java.security.spec.X509EncodedKeySpec;
import java.util.List;

/**
 * @author shuwei.wang
 * @description:
 */
public interface X509Req extends AutoCloseable{

    List<X509Attribute> getSubject();

    X509EncodedKeySpec getPublickey();

    String getDigestAlgorithm();

    byte[] encode();

    void parse();
}
