package com.shuwill.openssl.natives;

import com.shuwill.openssl.natives.pointer.ASN1_INTEGER;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;
import com.shuwill.openssl.natives.pointer.ASN1_OCTET_STRING;
import com.shuwill.openssl.natives.pointer.ASN1_TIME;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.EVP_MD;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.X509;
import com.shuwill.openssl.natives.pointer.X509V3_CTX;
import com.shuwill.openssl.natives.pointer.X509_PUBKEY;
import com.shuwill.openssl.natives.pointer.X509_EXTENSION;
import com.shuwill.openssl.natives.pointer.X509_NAME;
import com.shuwill.openssl.natives.pointer.X509_REQ;

/**
 * @author shuwei.wang
 * @description:
 */
public interface X509Native extends CommonNative {

    X509 X509_new();

    void X509_free(X509 x);

    X509_NAME X509_NAME_new();

    void X509_NAME_free(X509_NAME name);

    int X509_NAME_add_entry_by_txt(X509_NAME name, String field, byte[] value);

    int X509_set_version(X509 x, long version);

    long X509_get_version(X509 x);

    int X509_set_notBefore(X509 x, ASN1_TIME tm);

    int X509_set_notAfter(X509 x, ASN1_TIME tm);

    int X509_set_serialNumber(X509 x, ASN1_INTEGER serial);

    int X509_set_subject_name(X509 x, X509_NAME name);

    X509_NAME X509_get_subject_name(X509 a);

    int X509_set_issuer_name(X509 x, X509_NAME name);

    X509_NAME X509_get_issuer_name(X509 a);

    int X509_set_pubkey(X509 x, EVP_PKEY pkey);

    int X509_add_ext(X509 x, X509_EXTENSION ex, int loc);

    X509_EXTENSION X509_EXTENSION_new();

    void X509_EXTENSION_free(X509_EXTENSION ex);

    X509_EXTENSION X509V3_EXT_nconf_nid(X509V3_CTX ctx, int ext_nid, String value);

    X509_EXTENSION X509V3_EXT_i2d(int ext_nid, int crit, ASN1_OCTET_STRING ext_struc);

    int X509_sign(X509 x, EVP_PKEY pkey, EVP_MD md);

    int i2d_X509_bio(BIO bp, X509 x509);

    X509 d2i_X509_bio(BIO bp);

    X509_REQ X509_REQ_new();

    void X509_REQ_free(X509_REQ req);

    int X509_REQ_set_subject_name(X509_REQ req, X509_NAME name);

    X509_NAME X509_REQ_get_subject_name(X509_REQ req);

    int X509_REQ_set_pubkey(X509_REQ x, EVP_PKEY pkey);

    int X509_REQ_sign(X509_REQ x, EVP_PKEY pkey, EVP_MD md);

    int i2d_X509_REQ_bio(BIO bp, X509_REQ req);

    X509_REQ d2i_X509_REQ_bio(BIO bp);

    String X509_NAME_oneline(X509_NAME a);

    int X509_print(BIO bp, X509 x);

    X509_PUBKEY X509_get_X509_PUBKEY(X509 x);

    int X509_PUBKEY_set_param(X509_PUBKEY pub, ASN1_OBJECT aobj);
}
