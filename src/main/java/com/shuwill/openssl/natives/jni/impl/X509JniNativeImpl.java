package com.shuwill.openssl.natives.jni.impl;

import com.shuwill.openssl.natives.X509Native;
import com.shuwill.openssl.natives.jni.X509JniNative;
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

import java.nio.ByteBuffer;

import static com.shuwill.openssl.natives.ASN1Native.MBSTRING_UTF8;

public class X509JniNativeImpl extends CommonJniNativeImpl implements X509Native {

    @Override
    public X509 X509_new() {
        return new X509(X509JniNative.X509New(), this);
    }

    @Override
    public void X509_free(X509 x) {
        X509JniNative.X509Free(x.addr(Long.class));
    }

    @Override
    public X509_NAME X509_NAME_new() {
        return new X509_NAME(X509JniNative.X509NameNew(), this);
    }

    @Override
    public void X509_NAME_free(X509_NAME name) {
        X509JniNative.X509NameFree(name.addr(Long.class));
    }

    @Override
    public int X509_NAME_add_entry_by_txt(X509_NAME name, String field, byte[] value) {
        final ByteBuffer buffer = ByteBuffer.allocateDirect(value.length);
        buffer.put(value);
        return X509JniNative.X509NameAddEntryByTxt(name.addr(Long.class), field, MBSTRING_UTF8, buffer, value.length, -1, 0);
    }

    @Override
    public int X509_set_version(X509 x, long version) {
        return X509JniNative.X509SetVersion(x.addr(Long.class), version);
    }

    @Override
    public long X509_get_version(X509 x) {
        return X509JniNative.X509GetVersion(x.addr(Long.class));
    }

    @Override
    public int X509_set_notBefore(X509 x, ASN1_TIME tm) {
        return X509JniNative.X509SetNotBefore(x.addr(Long.class), tm.addr(Long.class));
    }

    @Override
    public int X509_set_notAfter(X509 x, ASN1_TIME tm) {
        return X509JniNative.X509SetNotAfter(x.addr(Long.class), tm.addr(Long.class));
    }

    @Override
    public int X509_set_serialNumber(X509 x, ASN1_INTEGER serial) {
        return X509JniNative.X509SetSerialNumber(x.addr(Long.class), serial.addr(Long.class));
    }

    @Override
    public int X509_set_subject_name(X509 x, X509_NAME name) {
        return X509JniNative.X509SetSubjectName(x.addr(Long.class), name.addr(Long.class));
    }

    @Override
    public X509_NAME X509_get_subject_name(X509 a) {
        return new X509_NAME(X509JniNative.X509GetSubjectName(a.addr(Long.class)), this);
    }

    @Override
    public int X509_set_issuer_name(X509 x, X509_NAME name) {
        return X509JniNative.X509SetIssuerName(x.addr(Long.class), name.addr(Long.class));
    }

    @Override
    public X509_NAME X509_get_issuer_name(X509 a) {
        return new X509_NAME(X509JniNative.X509GetIssuerName(a.addr(Long.class)), this);
    }

    @Override
    public int X509_set_pubkey(X509 x, EVP_PKEY pkey) {
        return X509JniNative.X509SetPubkey(x.addr(Long.class), pkey.addr(Long.class));
    }

    @Override
    public int X509_add_ext(X509 x, X509_EXTENSION ex, int loc) {
        return X509JniNative.X509AddExt(x.addr(Long.class), ex.addr(Long.class), loc);
    }

    @Override
    public X509_EXTENSION X509_EXTENSION_new() {
        return new X509_EXTENSION(X509JniNative.X509ExtensionNew(), this);
    }

    @Override
    public void X509_EXTENSION_free(X509_EXTENSION ex) {
        X509JniNative.X509ExtensionFree(ex.addr(Long.class));
    }

    @Override
    public X509_EXTENSION X509V3_EXT_nconf_nid(X509V3_CTX ctx, int ext_nid, String value) {
        Long issuer_addr = ctx.issuer_cert == null ? 0L : ctx.issuer_cert.addr(Long.class);
        Long subject_addr =  ctx.subject_cert == null ? 0L: ctx.subject_cert.addr(Long.class);
        return new X509_EXTENSION(X509JniNative.X509V3ExtNconfNid(ext_nid, value, issuer_addr, subject_addr, 0, 0, 0), this);
    }

    @Override
    public X509_EXTENSION X509V3_EXT_i2d(int ext_nid, int crit, ASN1_OCTET_STRING ext_struc) {
        return new X509_EXTENSION(X509JniNative.X509V3ExtI2d(ext_nid, crit, ext_struc.addr(Long.class)), this);
    }

    @Override
    public int X509_sign(X509 x, EVP_PKEY pkey, EVP_MD md) {
        return X509JniNative.X509Sign(x.addr(Long.class), pkey.addr(Long.class), md.addr(Long.class));
    }

    @Override
    public int i2d_X509_bio(BIO bp, X509 x509) {
        return X509JniNative.i2dX509Bio(bp.addr(Long.class), x509.addr(Long.class));
    }

    @Override
    public X509 d2i_X509_bio(BIO bp) {
        return new X509(X509JniNative.d2iX509Bio(bp.addr(Long.class)), this);
    }

    @Override
    public X509_REQ X509_REQ_new() {
        return new X509_REQ(X509JniNative.X509ReqNew(), this);
    }

    @Override
    public void X509_REQ_free(X509_REQ req) {
        X509JniNative.X509ReqFree(req.addr(Long.class));
    }

    @Override
    public int X509_REQ_set_subject_name(X509_REQ req, X509_NAME name) {
        return X509JniNative.X509ReqSetSubjectName(req.addr(Long.class), name.addr(Long.class));
    }

    @Override
    public X509_NAME X509_REQ_get_subject_name(X509_REQ req) {
        return new X509_NAME(X509JniNative.X509ReqGetSubjectName(req.addr(Long.class)), this);
    }

    @Override
    public int X509_REQ_set_pubkey(X509_REQ x, EVP_PKEY pkey) {
        return X509JniNative.X509ReqSetPubkey(x.addr(Long.class), pkey.addr(Long.class));
    }

    @Override
    public int X509_REQ_sign(X509_REQ x, EVP_PKEY pkey, EVP_MD md) {
        return X509JniNative.X509ReqSign(x.addr(Long.class), pkey.addr(Long.class), md.addr(Long.class));
    }

    @Override
    public int i2d_X509_REQ_bio(BIO bp, X509_REQ req) {
        return X509JniNative.i2dX509ReqBio(bp.addr(Long.class), req.addr(Long.class));
    }

    @Override
    public X509_REQ d2i_X509_REQ_bio(BIO bp) {
        return new X509_REQ(X509JniNative.d2iX509ReqBio(bp.addr(Long.class)), this);
    }

    @Override
    public String X509_NAME_oneline(X509_NAME a) {
        return X509JniNative.X509NameOneline(a.addr(Long.class));
    }

    @Override
    public int X509_print(BIO bp, X509 x) {
        return X509JniNative.X509Print(bp.addr(Long.class), x.addr(Long.class));
    }

    @Override
    public X509_PUBKEY X509_get_X509_PUBKEY(X509 x) {
        return new X509_PUBKEY(X509JniNative.X509GetX509Pubkey(x.addr(Long.class)), this);
    }

    @Override
    public int X509_PUBKEY_set_param(X509_PUBKEY pub, ASN1_OBJECT aobj) {
        return X509JniNative.X509PubkeySetParam(pub.addr(Long.class), aobj.addr(Long.class));
    }
}
