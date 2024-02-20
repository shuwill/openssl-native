package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.EvpNative;

/**
 * @author shuwei.wang
 * @description:
 */
public class EVP_PKEY extends EvpPointer {

    public EVP_PKEY(Object addr, EvpNative evpNative) {
        super(addr, evpNative);
    }

    @Override
    protected void doClose() throws Exception {
        evpNative.EVP_PKEY_free(this);
    }
}
