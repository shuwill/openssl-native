package com.shuwill.openssl.x509;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class KeyUsage extends Extension implements Serializable {

    private static final long serialVersionUID = 2126463323347163936L;

    private final boolean critical;
    private final boolean digitalSignature;
    private final boolean nonRepudiation;
    private final boolean keyEncipherment;
    private final boolean dataEncipherment;
    private final boolean keyAgreement;
    private final boolean keyCertSign;
    private final boolean crlSign;
    private final boolean encipherOnly;
    private final boolean decipherOonly;

    private KeyUsage(
            boolean critical, boolean digitalSignature, boolean nonRepudiation,
            boolean keyEncipherment, boolean dataEncipherment, boolean keyAgreement,
            boolean keyCertSign, boolean crlSign,
            boolean encipherOnly, boolean decipherOonly,
            ExtensionContext extensionContext
    ) {
        super("keyUsage", extensionContext);
        this.critical = critical;
        this.digitalSignature = digitalSignature;
        this.nonRepudiation = nonRepudiation;
        this.keyEncipherment = keyEncipherment;
        this.dataEncipherment = dataEncipherment;
        this.keyAgreement = keyAgreement;
        this.keyCertSign = keyCertSign;
        this.crlSign = crlSign;
        this.encipherOnly = encipherOnly;
        this.decipherOonly = decipherOonly;
    }

    public boolean isCritical() {
        return critical;
    }

    public boolean isDigitalSignature() {
        return digitalSignature;
    }

    public boolean isNonRepudiation() {
        return nonRepudiation;
    }

    public boolean isKeyEncipherment() {
        return keyEncipherment;
    }

    public boolean isDataEncipherment() {
        return dataEncipherment;
    }

    public boolean isKeyAgreement() {
        return keyAgreement;
    }

    public boolean isKeyCertSign() {
        return keyCertSign;
    }

    public boolean isCrlSign() {
        return crlSign;
    }

    public boolean isEncipherOnly() {
        return encipherOnly;
    }

    public boolean isDecipherOonly() {
        return decipherOonly;
    }

    public static KeyUsageBuilder builder() {
        return new KeyUsageBuilder();
    }

    @Override
    public String toString() {
        List<String> keyUsage = new ArrayList<>();
        if(critical) {
            keyUsage.add("critical");
        }
        if(digitalSignature) {
            keyUsage.add("digitalSignature");
        }
        if(nonRepudiation) {
            keyUsage.add("nonRepudiation");
        }
        if(keyEncipherment) {
            keyUsage.add("keyEncipherment");
        }
        if(dataEncipherment) {
            keyUsage.add("dataEncipherment");
        }
        if(keyAgreement) {
            keyUsage.add("keyAgreement");
        }
        if(keyCertSign) {
            keyUsage.add("keyCertSign");
        }
        if(crlSign) {
            keyUsage.add("cRLSign");
        }
        if(encipherOnly) {
            keyUsage.add("encipherOnly");
        }
        if(decipherOonly) {
            keyUsage.add("decipherOnly");
        }
        return String.join(",", keyUsage);
    }

    public static class KeyUsageBuilder extends ExtensionBuilder{

        private boolean _critical;
        private boolean _digitalSignature;
        private boolean _nonRepudiation;
        private boolean _keyEncipherment;
        private boolean _dataEncipherment;
        private boolean _keyAgreement;
        private boolean _keyCertSign;
        private boolean _crlSign;
        private boolean _encipherOnly;
        private boolean _decipherOonly;

        public KeyUsageBuilder critical() {
            _critical = true;
            return this;
        }

        public KeyUsageBuilder digitalSignature() {
            _digitalSignature = true;
            return this;
        }

        public KeyUsageBuilder nonRepudiation() {
            _nonRepudiation = true;
            return this;
        }

        public KeyUsageBuilder keyEncipherment() {
            _keyEncipherment = true;
            return this;
        }

        public KeyUsageBuilder dataEncipherment() {
            _dataEncipherment = true;
            return this;
        }

        public KeyUsageBuilder keyAgreement() {
            _keyAgreement = true;
            return this;
        }

        public KeyUsageBuilder keyCertSign() {
            _keyCertSign = true;
            return this;
        }

        public KeyUsageBuilder crlSign() {
            _crlSign = true;
            return this;
        }

        public KeyUsageBuilder _encipherOnly() {
            _encipherOnly = true;
            return this;
        }

        public KeyUsageBuilder decipherOonly() {
            _decipherOonly = true;
            return this;
        }

        public KeyUsageBuilder context(ExtensionContext extensionContext) {
            super._extensionContext = extensionContext;
            return this;
        }

        public KeyUsage build() {
            return new KeyUsage(
                    _critical,
                    _digitalSignature,
                    _nonRepudiation,
                    _keyEncipherment,
                    _dataEncipherment,
                    _keyAgreement,
                    _keyCertSign,
                    _crlSign,
                    _encipherOnly,
                    _decipherOonly,
                    super._extensionContext
            );
        }
    }
}
