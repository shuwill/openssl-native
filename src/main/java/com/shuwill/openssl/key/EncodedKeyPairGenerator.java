package com.shuwill.openssl.key;

/**
 * @author shuwei.wang
 * @description:
 */
public interface EncodedKeyPairGenerator extends AutoCloseable{

    void initialize(int keysize);

    void setCurveAlgorithm(String curveAlgorithm);

    EncodedKeyPair generateKeyPair();
}
