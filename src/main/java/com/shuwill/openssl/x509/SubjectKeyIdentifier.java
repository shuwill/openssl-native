package com.shuwill.openssl.x509;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class SubjectKeyIdentifier extends Extension implements Serializable {

    private static final long serialVersionUID = -321800416193171472L;

    private final boolean critical;
    private final boolean hash;

    public SubjectKeyIdentifier(boolean critical, boolean hash, ExtensionContext extensionContext) {
        super("subjectKeyIdentifier", extensionContext);
        this.critical = critical;
        this.hash = hash;
    }

    public boolean isCritical() {
        return critical;
    }

    public boolean isHash() {
        return hash;
    }

    @Override
    public String toString() {
        List<String> keyUsage = new ArrayList<>();
        if(critical) {
            keyUsage.add("critical");
        }
        if(hash) {
            keyUsage.add("hash");
        }
        return String.join(",", keyUsage);
    }

    public static SubjectKeyIdentifierBuilder builder() {
        return new SubjectKeyIdentifierBuilder();
    }

    public static class SubjectKeyIdentifierBuilder extends ExtensionBuilder{

        private boolean _critical;
        private boolean _hash;

        public SubjectKeyIdentifierBuilder critical() {
            this._critical = true;
            return this;
        }

        public SubjectKeyIdentifierBuilder hash(){
            this._hash = true;
            return this;
        }
        public SubjectKeyIdentifierBuilder context(ExtensionContext extensionContext) {
            super._extensionContext = extensionContext;
            return this;
        }

        public SubjectKeyIdentifier build() {
            return new SubjectKeyIdentifier(_critical, _hash, super._extensionContext);
        }
    }
}
