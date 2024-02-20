package com.shuwill.openssl.natives;

import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.BIO_METHOD;

import java.nio.IntBuffer;
import java.util.UUID;

public abstract class Nativeable implements AutoCloseable{

    private final UUID uuid;
    private final CommonNative commonNative;

    private int bioBufferSize = 8192;

    protected Nativeable(CommonNative commonNative) {
        this.uuid = UUID.randomUUID();
        this.commonNative = commonNative;
        NativeResource.init(this.uuid);
    }

    public UUID uuid() {
        return uuid;
    }

    @Override
    public void close() {
        NativeResource.clear(this.uuid);
    }

    protected void setBioBufferSize(int bufferSize) {
        this.bioBufferSize = bufferSize;
    }

    protected BIO createBIO() {
        final BIO_METHOD biom = commonNative.throwOnError(commonNative::BIO_s_mem, this);
        return commonNative.throwOnError(() -> commonNative.BIO_new(biom), this);
    }

    protected byte[] readBio(BIO bio) {
        byte[] buffer = new byte[bioBufferSize];
        final IntBuffer readbytes = IntBuffer.allocate(1);
        this.commonNative.throwOnError(commonNative.BIO_read_ex(
                bio,
                buffer,
                buffer.length,
                readbytes
        ), this);

        final int length = readbytes.get();
        byte[] result = new byte[length];
        System.arraycopy(buffer, 0, result, 0, length);
        return result;
    }

    protected int writeBio(BIO bio, byte[] content) {
        return commonNative.BIO_write(bio, content, content.length);
    }
}
