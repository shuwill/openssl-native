package com.shuwill.openssl.natives.jna.impl;

import com.shuwill.openssl.natives.X509Native;
import com.shuwill.openssl.natives.jna.JNA_X509V3_CTX;
import com.shuwill.openssl.natives.jna.X509JnaNative;
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
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;

import static com.shuwill.openssl.natives.ASN1Native.MBSTRING_UTF8;

public class X509JnaNativeImpl extends CommonJnaNativeImpl implements X509Native {

    private final X509JnaNative x509JnaNative;

    public X509JnaNativeImpl(X509JnaNative x509JnaNative) {
        super(x509JnaNative);
        this.x509JnaNative = x509JnaNative;
    }

    @Override
    public X509 X509_new() {
        return new X509(x509JnaNative.X509_new(), this);
    }

    @Override
    public void X509_free(X509 x) {
        x509JnaNative.X509_free(x.addr(Pointer.class));
    }

    @Override
    public X509_NAME X509_NAME_new() {
        return new X509_NAME(x509JnaNative.X509_NAME_new(), this);
    }

    @Override
    public void X509_NAME_free(X509_NAME name) {
        x509JnaNative.X509_NAME_free(name.addr(Pointer.class));
    }

    @Override
    public int X509_NAME_add_entry_by_txt(X509_NAME name, String field, byte[] value) {
        return x509JnaNative.X509_NAME_add_entry_by_txt(name.addr(Pointer.class), field, MBSTRING_UTF8, value, value.length, -1, 0);
    }

    @Override
    public int X509_set_version(X509 x, long version) {
        return x509JnaNative.X509_set_version(x.addr(Pointer.class), version);
    }

    @Override
    public long X509_get_version(X509 x) {
        return x509JnaNative.X509_get_version(x.addr(Pointer.class));
    }

    @Override
    public int X509_set_notBefore(X509 x, ASN1_TIME tm) {
        return x509JnaNative.X509_set1_notBefore(x.addr(Pointer.class), tm.addr(Pointer.class));
    }

    @Override
    public int X509_set_notAfter(X509 x, ASN1_TIME tm) {
        return x509JnaNative.X509_set1_notAfter(x.addr(Pointer.class), tm.addr(Pointer.class));
    }

    @Override
    public int X509_set_serialNumber(X509 x, ASN1_INTEGER serial) {
        return x509JnaNative.X509_set_serialNumber(x.addr(Pointer.class), serial.addr(Pointer.class));
    }

    @Override
    public int X509_set_subject_name(X509 x, X509_NAME name) {
        return x509JnaNative.X509_set_subject_name(x.addr(Pointer.class), name.addr(Pointer.class));
    }

    @Override
    public X509_NAME X509_get_subject_name(X509 a) {
        return new X509_NAME(x509JnaNative.X509_get_subject_name(a.addr(Pointer.class)), this);
    }

    @Override
    public int X509_set_issuer_name(X509 x, X509_NAME name) {
        return x509JnaNative.X509_set_issuer_name(x.addr(Pointer.class), name.addr(Pointer.class));
    }

    @Override
    public X509_NAME X509_get_issuer_name(X509 a) {
        return new X509_NAME(x509JnaNative.X509_get_issuer_name(a.addr(Pointer.class)), this);
    }

    @Override
    public int X509_set_pubkey(X509 x, EVP_PKEY pkey) {
        return x509JnaNative.X509_set_pubkey(x.addr(Pointer.class), pkey.addr(Pointer.class));
    }

    @Override
    public int X509_add_ext(X509 x, X509_EXTENSION ex, int loc) {
        return x509JnaNative.X509_add_ext(x.addr(Pointer.class), ex.addr(Pointer.class), loc);
    }

    @Override
    public X509_EXTENSION X509_EXTENSION_new() {
        return new X509_EXTENSION(x509JnaNative.X509_EXTENSION_new(), this);
    }

    @Override
    public void X509_EXTENSION_free(X509_EXTENSION ex) {
        x509JnaNative.X509_EXTENSION_free(ex.addr(Pointer.class));
    }

    @Override
    public X509_EXTENSION X509V3_EXT_nconf_nid(X509V3_CTX ctx, int ext_nid, String value) {
        final JNA_X509V3_CTX x509V3_ctx = new JNA_X509V3_CTX();
        Pointer issuer_addr = ctx.issuer_cert == null ? null : ctx.issuer_cert.addr(Pointer.class);
        Pointer subject_addr = ctx.subject_cert == null ? null : ctx.subject_cert.addr(Pointer.class);
        x509JnaNative.X509V3_set_ctx(x509V3_ctx, issuer_addr, subject_addr, null, null, ctx.flags);
        return new X509_EXTENSION(x509JnaNative.X509V3_EXT_nconf_nid(null, x509V3_ctx, ext_nid, value), this);
    }

    @Override
    public X509_EXTENSION X509V3_EXT_i2d(int ext_nid, int crit, ASN1_OCTET_STRING ext_struc) {
        return new X509_EXTENSION(x509JnaNative.X509V3_EXT_i2d(ext_nid, crit, ext_struc.addr(Pointer.class)), this);
    }

    @Override
    public int X509_sign(X509 x, EVP_PKEY pkey, EVP_MD md) {
        return x509JnaNative.X509_sign(x.addr(Pointer.class), pkey.addr(Pointer.class), md.addr(Pointer.class));
    }

    @Override
    public int i2d_X509_bio(BIO bp, X509 x509) {
        return x509JnaNative.i2d_X509_bio(bp.addr(Pointer.class), x509.addr(Pointer.class));
    }

    @Override
    public X509 d2i_X509_bio(BIO bp) {
        return new X509(x509JnaNative.d2i_X509_bio(bp.addr(Pointer.class), null), this);
    }

    @Override
    public X509_REQ X509_REQ_new() {
        return new X509_REQ(x509JnaNative.X509_REQ_new(), this);
    }

    @Override
    public void X509_REQ_free(X509_REQ req) {
        x509JnaNative.X509_REQ_free(req.addr(Pointer.class));
    }

    @Override
    public int X509_REQ_set_subject_name(X509_REQ req, X509_NAME name) {
        return x509JnaNative.X509_REQ_set_subject_name(req.addr(Pointer.class), name.addr(Pointer.class));
    }

    @Override
    public X509_NAME X509_REQ_get_subject_name(X509_REQ req) {
        return new X509_NAME(x509JnaNative.X509_REQ_get_subject_name(req.addr(Pointer.class)), this);
    }

    @Override
    public int X509_REQ_set_pubkey(X509_REQ x, EVP_PKEY pkey) {
        return x509JnaNative.X509_REQ_set_pubkey(x.addr(Pointer.class), pkey.addr(Pointer.class));
    }

    @Override
    public int X509_REQ_sign(X509_REQ x, EVP_PKEY pkey, EVP_MD md) {
        return x509JnaNative.X509_REQ_sign(x.addr(Pointer.class), pkey.addr(Pointer.class), md.addr(Pointer.class));
    }

    @Override
    public int i2d_X509_REQ_bio(BIO bp, X509_REQ req) {
        return x509JnaNative.i2d_X509_REQ_bio(bp.addr(Pointer.class), req.addr(Pointer.class));
    }

    @Override
    public X509_REQ d2i_X509_REQ_bio(BIO bp) {
        return new X509_REQ(x509JnaNative.d2i_X509_REQ_bio(bp.addr(Pointer.class), null), this);
    }

    @Override
    public String X509_NAME_oneline(X509_NAME a) {
        byte[] buf = new byte[8192];
        return x509JnaNative.X509_NAME_oneline(a.addr(Pointer.class), ByteBuffer.wrap(buf), buf.length);
    }

    @Override
    public int X509_print(BIO bp, X509 x) {
        return x509JnaNative.X509_print(bp.addr(Pointer.class), x.addr(Pointer.class));
    }

    @Override
    public X509_PUBKEY X509_get_X509_PUBKEY(X509 x) {
        return new X509_PUBKEY(x509JnaNative.X509_get_X509_PUBKEY(x.addr(Pointer.class)), this);
    }

    @Override
    public int X509_PUBKEY_set_param(X509_PUBKEY pub, ASN1_OBJECT aobj) {
        return x509JnaNative.X509_PUBKEY_set0_param(
                pub.addr(Pointer.class), aobj.addr(Pointer.class),
                0, null,
                null, 0
        );
    }
}
