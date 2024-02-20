package com.shuwill.openssl.x509;

import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.List;

public interface X509 extends AutoCloseable {

    int getVersion();

    long getSerialNumber();

    Calendar getNotBefore();

    Calendar getNotAfter();

    List<X509Attribute> getSubject();

    List<X509Attribute> getIssuer();

    X509EncodedKeySpec getPublickey();

    String getDigestAlgorithm();

    BasicConstraints getBasicConstraints();

    SubjectKeyIdentifier getSubjectKeyIdentifier();

    AuthorityKeyIdentifier getAuthorityKeyIdentifier();

    KeyUsage getKeyUsage();

    byte[] getEncoded();

    byte[] encode();

    String print();

    void parse();
}
