package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.CommonNative;

/**
 * @author shuwei.wang
 * @description:
 */
public class BIO_METHOD extends Pointer {

    private final CommonNative commonNative;

    public BIO_METHOD(Object addr, CommonNative commonNative) {
        super(addr);
        this.commonNative = commonNative;
    }

    @Override
    protected void doClose() {
        //commonNative.BIO_meth_free(this);
    }
}
