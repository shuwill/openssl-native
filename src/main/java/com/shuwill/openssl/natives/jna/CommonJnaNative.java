package com.shuwill.openssl.natives.jna;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

public interface CommonJnaNative extends Library {

    Pointer BIO_new(Pointer type);

    int BIO_free(Pointer a);

    Pointer BIO_s_mem();

    void BIO_meth_free(Pointer biom);

    int BIO_read(Pointer b, ByteBuffer data, int dlen);

    int BIO_read_ex(Pointer b, ByteBuffer data, int dlen, IntBuffer readbytes);

    int BIO_write(Pointer b, ByteBuffer data, int dlen);

    int BIO_write_ex(Pointer b, ByteBuffer data, int dlen, IntBuffer written);

    long ERR_peek_error();

    String ERR_error_string(long err, char[] null_);

}
