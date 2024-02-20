package com.shuwill.openssl.x509;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class AuthorityKeyIdentifier extends Extension implements Serializable {

    private static final long serialVersionUID = -3887307875598744095L;

    private final boolean critical;
    private final boolean keyid;
    private final boolean issuer;

    public AuthorityKeyIdentifier(boolean critical, boolean keyid, boolean issuer, ExtensionContext extensionContext) {
        super("authorityKeyIdentifier", extensionContext);
        this.critical = critical;
        this.keyid = keyid;
        this.issuer = issuer;
    }

    public boolean isCritical() {
        return critical;
    }

    public boolean isKeyid() {
        return keyid;
    }

    public boolean isIssuer() {
        return issuer;
    }

    public static AuthorityKeyIdentifierBuilder builder() {
        return new AuthorityKeyIdentifierBuilder();
    }

    @Override
    public String toString() {
        List<String> constraints = new ArrayList<>();
        if(critical) {
            constraints.add("critical");
        }
        if(keyid) {
            constraints.add("keyid:always");
        }
        if(issuer ) {
            constraints.add("issuer:always");
        }
        return String.join(",", constraints);
    }

    public static class AuthorityKeyIdentifierBuilder extends ExtensionBuilder{

        private boolean _critical;
        private boolean _keyid;
        private boolean _issuer;

        public AuthorityKeyIdentifierBuilder critical() {
            this._critical = true;
            return this;
        }

        public AuthorityKeyIdentifierBuilder keyid(){
            this._keyid = true;
            return this;
        }

        public AuthorityKeyIdentifierBuilder issuer() {
            this._issuer = true;
            return this;
        }

        public AuthorityKeyIdentifierBuilder context(ExtensionContext extensionContext) {
            super._extensionContext = extensionContext;
            return this;
        }

        public AuthorityKeyIdentifier build() {
            return new AuthorityKeyIdentifier(_critical, _keyid, _issuer, super._extensionContext);
        }
    }
}
