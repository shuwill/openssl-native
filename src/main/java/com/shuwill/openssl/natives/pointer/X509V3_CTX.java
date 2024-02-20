package com.shuwill.openssl.natives.pointer;


public class X509V3_CTX {

    public int flags;
    public X509 issuer_cert;
    public X509 subject_cert;
    public EVP_PKEY issuer_pkey;

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public X509 getIssuer_cert() {
        return issuer_cert;
    }

    public void setIssuer_cert(X509 issuer_cert) {
        this.issuer_cert = issuer_cert;
    }

    public X509 getSubject_cert() {
        return subject_cert;
    }

    public void setSubject_cert(X509 subject_cert) {
        this.subject_cert = subject_cert;
    }

    public EVP_PKEY getIssuer_pkey() {
        return issuer_pkey;
    }

    public void setIssuer_pkey(EVP_PKEY issuer_pkey) {
        this.issuer_pkey = issuer_pkey;
    }
}
