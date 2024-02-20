package com.shuwill.openssl.natives.pointer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author shuwei.wang
 * @description:
 */
public abstract class Pointer implements AutoCloseable{

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Object addr;

    protected Pointer(Object addr) {
        this.addr = addr;
    }

    public <T> T addr(Class<T> clazz) {
        if (this.addr == null) {
            return null;
        }
        return clazz.cast(this.addr);
    }

    public boolean isNull() {
        return addr == null || (addr instanceof Long && (Long) addr == 0);
    }

    private void preClose() {
        logger.debug("free the {}[{}]", getClass().getSimpleName(), this);
    }

    @Override
    public void close() throws Exception {
        preClose();
        if(!this.isNull()) {
            doClose();
        }
        afterClose();
    }

    protected abstract void doClose() throws Exception;

    private void afterClose() {

    }

    @Override
    public String toString() {
        if(this.isNull()) {
            return "addr[null]";
        } else {
            return this.addr instanceof Long ? "native@0x" + Long.toHexString((Long) this.addr) : this.addr.toString();
        }
    }
}
