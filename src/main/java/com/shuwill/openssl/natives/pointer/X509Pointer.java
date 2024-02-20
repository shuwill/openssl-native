package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.X509Native;

public abstract class X509Pointer extends Pointer{

    protected final X509Native x509Native;

    protected X509Pointer(Object addr, X509Native x509Native) {
        super(addr);
        this.x509Native = x509Native;
    }
}
