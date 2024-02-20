package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.EvpNative;

/**
 * @author shuwei.wang
 * @description:
 */
public class EVP_CIPHER extends EvpPointer {

    public EVP_CIPHER(Object addr, EvpNative evpNative) {
        super(addr, evpNative);
    }

    @Override
    protected void doClose() {
        evpNative.EVP_CIPHER_free(this);
    }
}
