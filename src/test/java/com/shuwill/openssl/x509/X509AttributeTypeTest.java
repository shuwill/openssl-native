package com.shuwill.openssl.x509;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509AttributeTypeTest {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Test
    public void testAttribute() {
        for (X509AttributeType value : X509AttributeType.values()) {
            final String oid = value.oid();
            final String txt = value.txt();
            if (oid.isEmpty()) {
                logger.error("{} not found in openssl definition.", value);
                continue;
            }
            logger.info("oid: {}, ln: {}", oid, txt);
        }
    }
}
