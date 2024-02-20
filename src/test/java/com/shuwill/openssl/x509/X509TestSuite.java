package com.shuwill.openssl.x509;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        RootCaCreatorTest.class,
        CertReqCreatorTest.class,
        CertCreatorTest.class
})
public class X509TestSuite {


}
