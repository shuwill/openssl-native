package com.shuwill.openssl.x509;

import java.io.Serializable;

public class X509Attribute implements Serializable {

    private static final long serialVersionUID = -3756126270015957557L;

    private final X509AttributeType type;
    private final String value;


    public X509Attribute(X509AttributeType type, String value) {
        this.type = type;
        this.value = value;
    }

    public X509AttributeType getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "[" + type + "=" + value + "]";
    }
}
