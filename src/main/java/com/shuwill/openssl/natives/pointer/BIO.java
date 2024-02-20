package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.CommonNative;

/**
 * @author shuwei.wang
 * @description:
 */
public class BIO extends Pointer {

    private final CommonNative commonNative;

    public BIO(Object addr, CommonNative commonNative) {
        super(addr);
        this.commonNative = commonNative;
    }

    @Override
    protected void doClose() throws Exception {
        commonNative.BIO_free(this);
    }
}
