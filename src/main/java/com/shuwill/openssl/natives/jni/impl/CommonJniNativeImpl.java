package com.shuwill.openssl.natives.jni.impl;

import com.shuwill.openssl.natives.AbstractCommonNative;
import com.shuwill.openssl.natives.CommonNative;
import com.shuwill.openssl.natives.jni.CommonJniNative;
import com.shuwill.openssl.natives.jni.NativeInt;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.BIO_METHOD;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;


public class CommonJniNativeImpl extends AbstractCommonNative implements CommonNative {

    @Override
    public BIO BIO_new(BIO_METHOD type) {
        return new BIO(CommonJniNative.bioNew(type.addr(Long.class)), this);
    }

    @Override
    public int BIO_free(BIO a) {
        return CommonJniNative.bioFree(a.addr(Long.class));
    }

    @Override
    public BIO_METHOD BIO_s_mem() {
        return new BIO_METHOD(CommonJniNative.bioMem(), this);
    }

    @Override
    public void BIO_meth_free(BIO_METHOD biom) {
        CommonJniNative.bioMethFree(biom.addr(Long.class));
    }

    @Override
    public int BIO_read(BIO b, byte[] data, int dlen) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(dlen);
        final int result = CommonJniNative.bioRead(b.addr(Long.class), buffer, dlen);
        buffer.get(data);
        return result;
    }

    @Override
    public int BIO_read_ex(BIO b, byte[] data, int dlen, IntBuffer readbytes) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(dlen);
        NativeInt readed = new NativeInt();
        final int result = CommonJniNative.bioReadEx(b.addr(Long.class), buffer, dlen, readed);
        readbytes.put(readed.value());
        readbytes.position(0);
        buffer.get(data);
        return result;
    }

    @Override
    public int BIO_write(BIO b, byte[] data, int dlen) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(dlen);
        buffer.put(data);
        return CommonJniNative.bioWrite(b.addr(Long.class), buffer, dlen);
    }

    @Override
    public int BIO_write_ex(BIO b, byte[] data, int dlen, IntBuffer written) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(dlen);
        buffer.put(data);
        NativeInt writed = new NativeInt();
        final int result = CommonJniNative.bioWriteEx(b.addr(Long.class), buffer, dlen, writed);
        written.put(writed.value());
        written.position(0);
        return result;
    }

    @Override
    public long ERR_peek_error() {
        return CommonJniNative.errPeekError();
    }

    @Override
    public String ERR_error_string(long err, char[] null_) {
        return CommonJniNative.errString(err, null_);
    }
}
