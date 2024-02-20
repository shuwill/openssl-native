package com.shuwill.openssl.natives.jni.impl;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.jni.ASN1JniNative;
import com.shuwill.openssl.natives.pointer.ASN1_INTEGER;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;
import com.shuwill.openssl.natives.pointer.ASN1_OCTET_STRING;
import com.shuwill.openssl.natives.pointer.ASN1_TIME;
import com.shuwill.openssl.natives.pointer.X509;

import java.nio.ByteBuffer;

public class Asn1JniNativeImpl extends CommonJniNativeImpl implements ASN1Native {

    @Override
    public ASN1_OBJECT OBJ_nid2obj(int n) {
        return new ASN1_OBJECT(ASN1JniNative.nid2obj(n), this);
    }

    @Override
    public String OBJ_nid2ln(int n) {
        return ASN1JniNative.nid2ln(n);
    }

    @Override
    public String OBJ_nid2sn(int n) {
        return ASN1JniNative.nid2sn(n);
    }

    @Override
    public int OBJ_obj2nid(ASN1_OBJECT o) {
        return ASN1JniNative.obj2nid(o.addr(Long.class));
    }

    @Override
    public int OBJ_ln2nid(String s) {
        return ASN1JniNative.ln2nid(s);
    }

    @Override
    public int OBJ_sn2nid(String s) {
        return ASN1JniNative.sn2nid(s);
    }

    @Override
    public int OBJ_txt2nid(String s) {
        return ASN1JniNative.txt2nid(s);
    }

    @Override
    public ASN1_OBJECT OBJ_txt2obj(String s, int no_name) {
        return new ASN1_OBJECT(ASN1JniNative.txt2obj(s, no_name), this);
    }

    @Override
    public int OBJ_obj2txt(byte[] buf, int buf_len, ASN1_OBJECT a, int no_name) {
        ByteBuffer d = ByteBuffer.allocateDirect(buf.length);
        final int result = ASN1JniNative.obj2txt(d, buf_len, a.addr(Long.class), no_name);
        d.get(buf);
        return result;
    }

    @Override
    public int OBJ_cmp(ASN1_OBJECT a, ASN1_OBJECT b) {
        return ASN1JniNative.cmp(a.addr(Long.class), b.addr(Long.class));
    }

    @Override
    public ASN1_OBJECT ASN1_OBJECT_new() {
        return new ASN1_OBJECT(ASN1JniNative.asn1ObjectNew(), this);
    }

    @Override
    public void ASN1_OBJECT_free(ASN1_OBJECT a) {
        ASN1JniNative.asn1ObjectFree(a.addr(Long.class));
    }

    @Override
    public ASN1_TIME ASN1_TIME_new() {
        return new ASN1_TIME(ASN1JniNative.asn1TimeNew(), this);
    }

    @Override
    public int ASN1_TIME_set_string(ASN1_TIME s, String str) {
        return ASN1JniNative.asn1TimeSetString(s.addr(Long.class), str);
    }

    @Override
    public ASN1_TIME X509_gmtime_adj(long adj) {
        return new ASN1_TIME(ASN1JniNative.X509GmtimeAdj(0, adj), this);
    }

    @Override
    public void ASN1_TIME_free(ASN1_TIME time) {
        ASN1JniNative.asn1TimeFree(time.addr(Long.class));
    }

    @Override
    public ASN1_INTEGER ASN1_INTEGER_new() {
        return new ASN1_INTEGER(ASN1JniNative.asn1IntegerNew(), this);
    }

    @Override
    public int ASN1_INTEGER_set(ASN1_INTEGER a, long v) {
        return ASN1JniNative.asn1IntegerSet(a.addr(Long.class), v);
    }

    @Override
    public void ASN1_INTEGER_free(ASN1_INTEGER a) {
        ASN1JniNative.asn1IntegerFree(a.addr(Long.class));
    }

    @Override
    public ASN1_OCTET_STRING ASN1_OCTET_STRING_new() {
        return new ASN1_OCTET_STRING(ASN1JniNative.asn1OctetStringNew(), this);
    }

    @Override
    public int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING str, byte[] data, int len) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(data.length);
        buffer.put(data);
        return ASN1JniNative.asn1OctetStringSet(str.addr(Long.class), buffer, len);
    }

    @Override
    public void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING str) {
        ASN1JniNative.asn1OctetStringFree(str.addr(Long.class));
    }

    @Override
    public ASN1_INTEGER X509_get_serialNumber(X509 x) {
        return new ASN1_INTEGER(ASN1JniNative.X509GetSerialNumber(x.addr(Long.class)), this);
    }

    @Override
    public ASN1_TIME X509_get_notBefore(X509 x) {
        return new ASN1_TIME(ASN1JniNative.X509GetNotAfter(x.addr(Long.class)), this);
    }

    @Override
    public ASN1_TIME X509_get_notAfter(X509 x) {
        return new ASN1_TIME(ASN1JniNative.X509GetNotAfter(x.addr(Long.class)), this);
    }
}
