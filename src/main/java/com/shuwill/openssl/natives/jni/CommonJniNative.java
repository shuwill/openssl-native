package com.shuwill.openssl.natives.jni;

import java.nio.ByteBuffer;

public class CommonJniNative {

    public static native long bioNew(long type);

    public static native int bioFree(long a);

    public static native long bioMem();

    public static native long bioMethFree(long biom);

    public static native int bioRead(long b, ByteBuffer data, int dlen);

    public static native int bioReadEx(long b, ByteBuffer data, long dlen, NativeInt readed);

    public static native int bioWrite(long b, ByteBuffer data, int dlen);

    public static native int bioWriteEx(long b, ByteBuffer data, long dlen, NativeInt written);

    public static native long errPeekError();

    public static native String errString(long err, char[] null_);
}
