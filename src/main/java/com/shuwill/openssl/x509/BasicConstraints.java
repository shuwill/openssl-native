package com.shuwill.openssl.x509;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class BasicConstraints extends Extension implements Serializable {

    private static final long serialVersionUID = -6185049052042910768L;

    private final boolean critical;
    private final boolean ca;
    private final int pathlen;

    private BasicConstraints(boolean critical, boolean ca, int pathlen, ExtensionContext extensionContext) {
        super("basicConstraints", extensionContext);
        this.critical = critical;
        this.ca = ca;
        this.pathlen = pathlen;
    }

    public boolean isCritical() {
        return critical;
    }

    public boolean isCa() {
        return ca;
    }

    public int getPathlen() {
        return pathlen;
    }

    public static BasicConstraintsBuilder builder() {
        return new BasicConstraintsBuilder();
    }

    @Override
    public String toString() {
        List<String> constraints = new ArrayList<>();
        if(critical) {
            constraints.add("critical");
        }
        if(ca) {
            constraints.add("CA:true");
        }
        if(pathlen > 0 ) {
            constraints.add("pathlen:" + pathlen);
        }
        return String.join(",", constraints);
    }

    public static class BasicConstraintsBuilder extends ExtensionBuilder{

        private boolean _critical;
        private boolean _ca;
        private int _pathlen;

        public BasicConstraintsBuilder critical() {
            this._critical = true;
            return this;
        }

        public BasicConstraintsBuilder ca(){
            this._ca = true;
            return this;
        }

        public BasicConstraintsBuilder pathlen(int pathlen) {
            this._pathlen = pathlen;
            return this;
        }

        public BasicConstraintsBuilder context(ExtensionContext extensionContext) {
            super._extensionContext = extensionContext;
            return this;
        }

        public BasicConstraints build() {
            return new BasicConstraints(_critical, _ca, _pathlen, super._extensionContext);
        }
    }
}
