package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.X509Native;

/**
 * @author shuwei.wang
 * @description:
 */
public class X509_REQ extends X509Pointer {

    public X509_REQ(Object addr, X509Native x509Native) {
        super(addr, x509Native);
    }

    @Override
    protected void doClose() throws Exception {
        x509Native.X509_REQ_free(this);
    }
}
