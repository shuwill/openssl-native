package com.shuwill.openssl.natives.jna.impl;

import com.shuwill.openssl.natives.AbstractCommonNative;
import com.shuwill.openssl.natives.CommonNative;
import com.shuwill.openssl.natives.jna.CommonJnaNative;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.BIO_METHOD;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

public class CommonJnaNativeImpl extends AbstractCommonNative implements CommonNative {

    private final CommonJnaNative commonJnaNative;

    public CommonJnaNativeImpl(CommonJnaNative commonJnaNative) {
        this.commonJnaNative = commonJnaNative;
    }

    @Override
    public BIO BIO_new(BIO_METHOD type) {
        return new BIO(commonJnaNative.BIO_new(type.addr(Pointer.class)), this);
    }

    @Override
    public int BIO_free(BIO a) {
        return commonJnaNative.BIO_free(a.addr(Pointer.class));
    }

    @Override
    public BIO_METHOD BIO_s_mem() {
        return new BIO_METHOD(commonJnaNative.BIO_s_mem(), this);
    }

    @Override
    public void BIO_meth_free(BIO_METHOD biom) {
        commonJnaNative.BIO_meth_free(biom.addr(Pointer.class));
    }

    @Override
    public int BIO_read(BIO b, byte[] data, int dlen) {
        return commonJnaNative.BIO_read(b.addr(Pointer.class), ByteBuffer.wrap(data), dlen);
    }

    @Override
    public int BIO_read_ex(BIO b, byte[] data, int dlen, IntBuffer readbytes) {
        return commonJnaNative.BIO_read_ex(b.addr(Pointer.class), ByteBuffer.wrap(data), dlen, readbytes);
    }

    @Override
    public int BIO_write(BIO b, byte[] data, int dlen) {
        return commonJnaNative.BIO_write(b.addr(Pointer.class), ByteBuffer.wrap(data), dlen);
    }

    @Override
    public int BIO_write_ex(BIO b, byte[] data, int dlen, IntBuffer written) {
        return commonJnaNative.BIO_write_ex(b.addr(Pointer.class), ByteBuffer.wrap(data), dlen, written);
    }

    @Override
    public long ERR_peek_error() {
        return commonJnaNative.ERR_peek_error();
    }

    @Override
    public String ERR_error_string(long err, char[] null_) {
        return commonJnaNative.ERR_error_string(err, null_);
    }
}
