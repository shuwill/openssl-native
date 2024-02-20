package com.shuwill.openssl.natives.jna;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.nio.ByteBuffer;

/**
 * @author shuwei.wang
 * @description:
 */
public interface X509JnaNative extends CommonJnaNative {

    Pointer X509_new();

    void X509_free(Pointer x);

    Pointer X509_NAME_new();

    void X509_NAME_free(Pointer name);

    int X509_NAME_add_entry_by_txt(Pointer name, String field, int type, byte[] bytes, int len, int loc, int set);

    int X509_set_version(Pointer x, long version);

    long X509_get_version(Pointer x);

    int X509_set1_notBefore(Pointer x, Pointer tm);

    int X509_set1_notAfter(Pointer x, Pointer tm);

    int X509_set_serialNumber(Pointer x, Pointer serial);

    int X509_set_subject_name(Pointer x, Pointer name);

    Pointer X509_get_subject_name(Pointer a);

    int X509_set_issuer_name(Pointer x, Pointer name);

    Pointer X509_get_issuer_name(Pointer a);

    int X509_set_pubkey(Pointer x, Pointer pkey);

    int X509_add_ext(Pointer x, Pointer ex, int loc);

    Pointer X509_EXTENSION_new();

    void X509_EXTENSION_free(Pointer ex);

    Pointer X509V3_EXT_nconf_nid(Pointer conf, JNA_X509V3_CTX ctx, int ext_nid, String value);

    void X509V3_set_ctx(JNA_X509V3_CTX ctx, Pointer issuer, Pointer subject, Pointer req, Pointer crl, int flags);

    Pointer X509V3_EXT_i2d(int ext_nid, int crit, Pointer ext_struc);

    int X509_sign(Pointer x, Pointer pkey, Pointer md);

    int i2d_X509_bio(Pointer bp, Pointer x509);

    Pointer d2i_X509_bio(Pointer bp, PointerByReference x509);

    Pointer X509_REQ_new();

    void X509_REQ_free(Pointer req);

    int X509_REQ_set_subject_name(Pointer req, Pointer name);

    Pointer X509_REQ_get_subject_name(Pointer req);

    int X509_REQ_set_pubkey(Pointer x, Pointer pkey);

    int X509_REQ_sign(Pointer x, Pointer pkey, Pointer md);

    int i2d_X509_REQ_bio(Pointer bp, Pointer req);

    Pointer d2i_X509_REQ_bio(Pointer bp, PointerByReference req);

    String X509_NAME_oneline(Pointer a, ByteBuffer buffer, int size);

    int X509_print(Pointer bp, Pointer x);

    Pointer X509_get_X509_PUBKEY(Pointer x);

    int X509_PUBKEY_set0_param(Pointer pub, Pointer aobj, int ptype, Pointer pval, Pointer penc, int penclen);
}
