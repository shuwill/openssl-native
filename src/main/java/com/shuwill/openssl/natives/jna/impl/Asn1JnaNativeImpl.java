package com.shuwill.openssl.natives.jna.impl;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.jna.Asn1JnaNative;
import com.shuwill.openssl.natives.pointer.ASN1_INTEGER;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;
import com.shuwill.openssl.natives.pointer.ASN1_OCTET_STRING;
import com.shuwill.openssl.natives.pointer.ASN1_TIME;
import com.shuwill.openssl.natives.pointer.X509;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;


public class Asn1JnaNativeImpl extends CommonJnaNativeImpl implements ASN1Native {

    private final Asn1JnaNative asn1JnaNative;

    public Asn1JnaNativeImpl(Asn1JnaNative asn1JnaNative) {
        super(asn1JnaNative);
        this.asn1JnaNative = asn1JnaNative;
    }

    @Override
    public ASN1_OBJECT OBJ_nid2obj(int n) {
        return new ASN1_OBJECT(asn1JnaNative.OBJ_nid2obj(n), this);
    }

    @Override
    public String OBJ_nid2ln(int n) {
        return asn1JnaNative.OBJ_nid2ln(n);
    }

    @Override
    public String OBJ_nid2sn(int n) {
        return asn1JnaNative.OBJ_nid2sn(n);
    }

    @Override
    public int OBJ_obj2nid(ASN1_OBJECT o) {
        return asn1JnaNative.OBJ_obj2nid(o.addr(Pointer.class));
    }

    @Override
    public int OBJ_ln2nid(String s) {
        return asn1JnaNative.OBJ_ln2nid(s);
    }

    @Override
    public int OBJ_sn2nid(String s) {
        return asn1JnaNative.OBJ_sn2nid(s);
    }

    @Override
    public int OBJ_txt2nid(String s) {
        return asn1JnaNative.OBJ_txt2nid(s);
    }

    @Override
    public ASN1_OBJECT OBJ_txt2obj(String s, int no_name) {
        return new ASN1_OBJECT(asn1JnaNative.OBJ_txt2obj(s, no_name), this);
    }

    @Override
    public int OBJ_obj2txt(byte[] buf, int buf_len, ASN1_OBJECT a, int no_name) {
        return asn1JnaNative.OBJ_obj2txt(ByteBuffer.wrap(buf), buf_len, a.addr(Pointer.class), no_name);
    }

    @Override
    public int OBJ_cmp(ASN1_OBJECT a, ASN1_OBJECT b) {
        return asn1JnaNative.OBJ_cmp(a.addr(Pointer.class), b.addr(Pointer.class));
    }

    @Override
    public ASN1_OBJECT ASN1_OBJECT_new() {
        return new ASN1_OBJECT(asn1JnaNative.ASN1_OBJECT_new(), this);
    }

    @Override
    public void ASN1_OBJECT_free(ASN1_OBJECT a) {
        asn1JnaNative.ASN1_OBJECT_free(a.addr(Pointer.class));
    }

    @Override
    public ASN1_TIME ASN1_TIME_new() {
        return new ASN1_TIME(asn1JnaNative.ASN1_TIME_new(), this);
    }

    @Override
    public int ASN1_TIME_set_string(ASN1_TIME s, String str) {
        return asn1JnaNative.ASN1_TIME_set_string(s.addr(Pointer.class), str);
    }

    @Override
    public ASN1_TIME X509_gmtime_adj(long adj) {
        return new ASN1_TIME(asn1JnaNative.X509_gmtime_adj(null, adj), this);
    }

    @Override
    public void ASN1_TIME_free(ASN1_TIME time) {
        asn1JnaNative.ASN1_TIME_free(time.addr(Pointer.class));
    }

    @Override
    public ASN1_INTEGER ASN1_INTEGER_new() {
        return new ASN1_INTEGER(asn1JnaNative.ASN1_INTEGER_new(), this);
    }

    @Override
    public int ASN1_INTEGER_set(ASN1_INTEGER a, long v) {
        return asn1JnaNative.ASN1_INTEGER_set(a.addr(Pointer.class), v);
    }

    @Override
    public void ASN1_INTEGER_free(ASN1_INTEGER a) {
        asn1JnaNative.ASN1_INTEGER_free(a.addr(Pointer.class));
    }

    @Override
    public ASN1_OCTET_STRING ASN1_OCTET_STRING_new() {
        return new ASN1_OCTET_STRING(asn1JnaNative.ASN1_OCTET_STRING_new(), this);
    }

    @Override
    public int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING str, byte[] data, int len) {
        return asn1JnaNative.ASN1_OCTET_STRING_set(str.addr(Pointer.class), data, len);
    }

    @Override
    public void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING str) {
        asn1JnaNative.ASN1_OCTET_STRING_free(str.addr(Pointer.class));
    }

    @Override
    public ASN1_TIME X509_get_notBefore(X509 x) {
        return new ASN1_TIME(asn1JnaNative.X509_get0_notBefore(x.addr(Pointer.class)), this);
    }

    @Override
    public ASN1_TIME X509_get_notAfter(X509 x) {
        return new ASN1_TIME(asn1JnaNative.X509_get0_notAfter(x.addr(Pointer.class)), this);
    }

    @Override
    public ASN1_INTEGER X509_get_serialNumber(X509 x) {
        return new ASN1_INTEGER(asn1JnaNative.X509_get_serialNumber(x.addr(Pointer.class)), this);
    }
}
