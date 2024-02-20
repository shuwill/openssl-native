package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.ASN1Native;

/**
 * @author shuwei.wang
 * @description:
 */
public class ASN1_TIME extends ASN1Pointer {

    public ASN1_TIME(Object addr, ASN1Native asn1Native) {
        super(addr, asn1Native);
    }

    @Override
    protected void doClose() {
        asn1Native.ASN1_TIME_free(this);
    }
}
