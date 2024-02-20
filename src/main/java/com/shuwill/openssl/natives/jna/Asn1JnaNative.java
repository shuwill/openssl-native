package com.shuwill.openssl.natives.jna;

import com.sun.jna.Pointer;

import java.nio.ByteBuffer;

public interface Asn1JnaNative extends CommonJnaNative {

    Pointer OBJ_nid2obj(int n);

    String OBJ_nid2ln(int n);

    String OBJ_nid2sn(int n);

    int OBJ_obj2nid(Pointer o);

    int OBJ_ln2nid(String s);

    int OBJ_sn2nid(String s);

    int OBJ_txt2nid(String s);

    Pointer OBJ_txt2obj(String s, int no_name);

    int OBJ_obj2txt(ByteBuffer buf, int buf_len, Pointer a, int no_name);

    int OBJ_cmp(Pointer a, Pointer b);

    Pointer ASN1_OBJECT_new();

    void ASN1_OBJECT_free(Pointer a);

    Pointer ASN1_TIME_new();

    int ASN1_TIME_set_string(Pointer s, String str);

    Pointer X509_gmtime_adj(Pointer s, long adj);

    void ASN1_TIME_free(Pointer time);

    Pointer ASN1_INTEGER_new();

    int ASN1_INTEGER_set(Pointer a, long v);

    void ASN1_INTEGER_free(Pointer a);

    Pointer ASN1_OCTET_STRING_new();

    int ASN1_OCTET_STRING_set(Pointer str, byte[] data, int len);

    void ASN1_OCTET_STRING_free(Pointer str);

    Pointer X509_get0_notBefore(Pointer x);

    Pointer X509_get0_notAfter(Pointer x);

    Pointer X509_get_serialNumber(Pointer x);

}
