package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.EvpNative;

/**
 * @author shuwei.wang
 * @description:
 */
public class EVP_PKEY_CTX extends EvpPointer {

    public EVP_PKEY_CTX(Object addr, EvpNative evpNative) {
        super(addr, evpNative);
    }

    @Override
    protected void doClose() throws Exception {
        evpNative.EVP_PKEY_CTX_free(this);
    }
}
