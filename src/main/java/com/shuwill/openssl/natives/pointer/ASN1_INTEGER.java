package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.ASN1Native;

/**
 * @author shuwei.wang
 * @description:
 */
public class ASN1_INTEGER extends ASN1Pointer {

    public ASN1_INTEGER(Object addr, ASN1Native asn1Native) {
       super(addr, asn1Native);
    }

    @Override
    public void doClose() {
        asn1Native.ASN1_INTEGER_free(this);
    }
}
