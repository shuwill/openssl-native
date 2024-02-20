package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.ASN1Native;

public abstract class ASN1Pointer extends Pointer{

    protected final ASN1Native asn1Native;

    protected ASN1Pointer(Object addr, ASN1Native asn1Native) {
        super(addr);
        this.asn1Native = asn1Native;
    }
}
