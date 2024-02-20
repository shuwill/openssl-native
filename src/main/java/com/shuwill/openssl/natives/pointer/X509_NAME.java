package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.X509Native;

/**
 * @author shuwei.wang
 * @description:
 */
public class X509_NAME extends X509Pointer {

    public X509_NAME(Object addr, X509Native x509Native) {
        super(addr, x509Native);
    }

    @Override
    protected void doClose() throws Exception {
        x509Native.X509_NAME_free(this);
    }
}
