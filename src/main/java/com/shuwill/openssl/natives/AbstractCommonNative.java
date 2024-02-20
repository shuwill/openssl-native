package com.shuwill.openssl.natives;

import com.shuwill.openssl.natives.pointer.Pointer;

import java.util.function.Predicate;
import java.util.function.Supplier;

public abstract class AbstractCommonNative implements CommonNative {

    @Override
    public void throwOnError(final int retVal, AutoCloseable closeable) {
        if (retVal != 1) {
            doThrowOnError(closeable, null);
        }
    }

    @Override
    public void throwOnError(Predicate<Integer> predicate, final int code, AutoCloseable closeable, String errdesc) {
        if (!predicate.test(code)) {
            doThrowOnError(closeable, errdesc);
        }
    }

    @Override
    public void throwOnError(Predicate<Integer> predicate, int code, AutoCloseable closeable) {
        throwOnError(predicate, code, closeable, "");
    }

    @Override
    public <P extends Pointer> P throwOnError(Supplier<P> supplier, Nativeable nativeable, String errdesc) {
        final P pointer = supplier.get();
        if (pointer.isNull()) {
            doThrowOnError(nativeable, errdesc);
        } else {
            NativeResource.add(nativeable.uuid(), pointer);
        }
        return pointer;
    }

    @Override
    public <P extends Pointer> P throwOnError(Supplier<P> supplier, Nativeable nativeable) {
        return throwOnError(supplier, nativeable, "");
    }

    @Override
    public <P extends Pointer> P throwOnError(Predicate<P> predicate, Supplier<P> supplier, Nativeable nativeable, String errdesc) {
        final P pointer = supplier.get();
        if (!predicate.test(pointer)) {
            doThrowOnError(nativeable, errdesc);
        } else {
            NativeResource.add(nativeable.uuid(), pointer);
        }
        return pointer;
    }

    @Override
    public <P extends Pointer> P throwOnError(Predicate<P> predicate, Supplier<P> supplier, Nativeable nativeable) {
        return throwOnError(predicate, supplier, nativeable, "");
    }

    private void doThrowOnError(AutoCloseable closeable, String errdesc) {
        try {
            final long err = ERR_peek_error();
            if (err != 0) {
                errdesc = ERR_error_string(err, null);
            }
            throw new IllegalArgumentException(errdesc);
        } finally {
            try {
                closeable.close();
            } catch (Exception ignore) {

            }
        }
    }
}
