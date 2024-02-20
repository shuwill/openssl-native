package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.EvpNative;

/**
 * @author shuwei.wang
 * @description:
 */
public class PKCS8_PRIV_KEY_INFO extends EvpPointer {

    public PKCS8_PRIV_KEY_INFO(Object addr, EvpNative evpNative) {
        super(addr, evpNative);
    }

    @Override
    protected void doClose() throws Exception {
        evpNative.PKCS8_PRIV_KEY_INFO_free(this);
    }
}
