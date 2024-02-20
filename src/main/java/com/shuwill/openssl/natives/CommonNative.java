package com.shuwill.openssl.natives;

import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.BIO_METHOD;
import com.shuwill.openssl.natives.pointer.Pointer;

import java.nio.IntBuffer;
import java.util.function.Predicate;
import java.util.function.Supplier;

public interface CommonNative{

    BIO BIO_new(BIO_METHOD type);

    int BIO_free(BIO a);

    BIO_METHOD BIO_s_mem();

    void BIO_meth_free(BIO_METHOD biom);

    int BIO_read(BIO b, byte[] data, int dlen);

    int BIO_read_ex(BIO b, byte[] data, int dlen, IntBuffer readbytes);

    int BIO_write(BIO b, byte[] data, int dlen);

    int BIO_write_ex(BIO b, byte[] data, int dlen, IntBuffer written);

    long ERR_peek_error();

    String ERR_error_string(long err, char[] null_);

    void throwOnError(final int code, AutoCloseable closeable);

    void throwOnError(final Predicate<Integer> predicate, final int code, AutoCloseable closeable, String errdesc);

    void throwOnError(final Predicate<Integer> predicate, final int code, AutoCloseable closeable);

    <P extends Pointer> P throwOnError(Supplier<P> supplier, Nativeable nativeable, String errdesc);

    <P extends Pointer> P throwOnError(Supplier<P> supplier, Nativeable nativeable);

    <P extends Pointer> P throwOnError(Predicate<P> predicate, Supplier<P> supplier, Nativeable nativeable, String errdesc);

    <P extends Pointer> P throwOnError(Predicate<P> predicate, Supplier<P> supplier, Nativeable nativeable);
}