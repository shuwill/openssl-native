package com.shuwill.openssl.natives.jna;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class JNA_X509V3_CTX extends Structure {

    public int flags;
    public Pointer issuer_cert;
    public Pointer subject_cert;
    public Pointer subject_req;
    public Pointer crl;
    public Pointer db_meth;
    public Pointer db;
    public Pointer issuer_pkey;

    public JNA_X509V3_CTX() {
        super();
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("flags", "issuer_cert", "subject_cert", "subject_req", "crl", "db_meth", "db", "issuer_pkey");
    }

    public JNA_X509V3_CTX(int flags, Pointer issuer_cert, Pointer subject_cert, Pointer subject_req, Pointer crl, Pointer db_meth, Pointer db, Pointer issuer_pkey) {
        super();
        this.flags = flags;
        this.issuer_cert = issuer_cert;
        this.subject_cert = subject_cert;
        this.subject_req = subject_req;
        this.crl = crl;
        this.db_meth = db_meth;
        this.db = db;
        this.issuer_pkey = issuer_pkey;
    }

    public JNA_X509V3_CTX(Pointer peer) {
        super(peer);
    }

    public static class ByReference extends JNA_X509V3_CTX implements Structure.ByReference {

    }

    public static class ByValue extends JNA_X509V3_CTX implements Structure.ByValue {

    }
}