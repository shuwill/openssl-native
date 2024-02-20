package com.shuwill.openssl.x509;

import java.io.Serializable;

public class ExtensionContext implements Serializable {

    private static final long serialVersionUID = -8465440458316979131L;

    private final int flags;
    private final X509 issuerCert;
    private final boolean issuerSelf;
    private final X509 subjectCert;
    private final boolean subjectSelf;
    private final byte[] issuerKey;

    private ExtensionContext(int flags, X509 issuerCert, boolean issuerSelf, X509 subjectCert, boolean subjectSelf, byte[] issuerKey) {
        this.flags = flags;
        this.issuerCert = issuerCert;
        this.issuerSelf = issuerSelf;
        this.subjectCert = subjectCert;
        this.subjectSelf = subjectSelf;
        this.issuerKey = issuerKey;
    }

    public int getFlags() {
        return flags;
    }

    public X509 getIssuerCert() {
        return issuerCert;
    }

    public boolean isIssuerSelf() {
        return issuerSelf;
    }

    public X509 getSubjectCert() {
        return subjectCert;
    }

    public boolean isSubjectSelf() {
        return subjectSelf;
    }

    public byte[] getIssuerKey() {
        return issuerKey;
    }

    public static ExtensionContextBuilder builder() {
        return new ExtensionContextBuilder();
    }

    public static class ExtensionContextBuilder {

        private int _flags = 0;
        private X509 _issuerCert;
        private boolean _issuerSelf;
        private X509 _subjectCert;
        private boolean _subjectSelf;
        private byte[] _issuerKey;

        public ExtensionContextBuilder flags(int flags){
            this._flags = flags;
            return this;
        }

        public ExtensionContextBuilder issuerCert(X509 issuerCert){
            this._issuerCert = issuerCert;
            return this;
        }

        public ExtensionContextBuilder issuerSelf(boolean issuerSelf){
            this._issuerSelf = issuerSelf;
            return this;
        }

        public ExtensionContextBuilder subjectCert(X509 subjectCert){
            this._subjectCert = subjectCert;
            return this;
        }

        public ExtensionContextBuilder subjectSelf(boolean subjectSelf){
            this._subjectSelf = subjectSelf;
            return this;
        }

        public ExtensionContextBuilder issuerKey(byte[] issuerKey){
            this._issuerKey = issuerKey;
            return this;
        }

        public ExtensionContext build() {
            return new ExtensionContext(
                    this._flags,
                    this._issuerCert,
                    this._issuerSelf,
                    this._subjectCert,
                    this._subjectSelf,
                    this._issuerKey
            );
        }
    }
}
