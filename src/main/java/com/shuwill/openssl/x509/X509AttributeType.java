package com.shuwill.openssl.x509;

import com.shuwill.openssl.common.OpensslNativeEnvironment;
import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;

import java.util.HashMap;
import java.util.Map;

/**
 * reference by <a href="https://www.rfc-editor.org/rfc/rfc4519">rfc4519</a>
 */
public enum X509AttributeType {

    businessCategory,
    C,
    CN,
    DC,
    description,
    destinationIndicator,
    distinguishedName,
    dnQualifier,
    enhancedSearchGuide,
    facsimileTelephoneNumber,
    generationQualifier,
    GN,
    houseIdentifier,
    initials,
    L,
    member,
    name,
    O,
    OU,
    owner,
    physicalDeliveryOfficeName,
    postalAddress,
    postalCode,
    postOfficeBox,
    preferredDeliveryMethod,
    registeredAddress,
    emailAddress,
    roleOccupant,
    searchGuide,
    seeAlso,
    serialNumber,
    SN,
    ST,
    street,
    telephoneNumber,
    teletexTerminalIdentifier,
    telexNumber,
    title,
    UID,
    uniqueMember,
    userPassword,
    x121Address,
    x500UniqueIdentifier;



    public String oid() {
        final ASN1Native asn1Native = OpensslNativeEnvironment.get().getNativeInterface(ASN1Native.class);
        final int nid = asn1Native.OBJ_sn2nid(this.name());
        final ASN1_OBJECT asn1_object = asn1Native.OBJ_nid2obj(nid);

        final byte[] buf = new byte[8192];
        final int len = asn1Native.OBJ_obj2txt(buf, buf.length, asn1_object, 1);

        final byte[] result = new byte[len];
        System.arraycopy(buf, 0, result, 0, result.length);
        return new String(result);
    }

    private static final Map<String, X509AttributeType> MAP = new HashMap<>();

    static {
        for (X509AttributeType value : X509AttributeType.values()) {
            MAP.put(value.name().toUpperCase(), value);
        }
    }

    public String txt() {
        final ASN1Native asn1Native = OpensslNativeEnvironment.get().getNativeInterface(ASN1Native.class);
        final int nid = asn1Native.OBJ_sn2nid(this.name());
        return asn1Native.OBJ_nid2ln(nid);
    }

    public static X509AttributeType get(String name) {
        return MAP.get(name.toUpperCase());
    }
}