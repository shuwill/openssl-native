package com.shuwill.openssl.natives.pointer;

import com.shuwill.openssl.natives.EvpNative;

public abstract class EvpPointer extends Pointer{

    protected final EvpNative evpNative;

    protected EvpPointer(Object addr, EvpNative evpNative) {
        super(addr);
        this.evpNative = evpNative;
    }

}
