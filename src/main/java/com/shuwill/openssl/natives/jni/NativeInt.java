package com.shuwill.openssl.natives.jni;

public class NativeInt {

    private final int value;

    public NativeInt(final int value) {
        this.value = value;
    }

    public NativeInt() {
        this(0);
    }

    public int value() {
        return value;
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }
}
