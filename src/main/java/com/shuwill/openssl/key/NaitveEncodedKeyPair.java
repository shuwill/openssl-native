package com.shuwill.openssl.key;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.Nativeable;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;

import javax.crypto.EncryptedPrivateKeyInfo;
import java.io.IOException;
import java.io.Serializable;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class NaitveEncodedKeyPair extends Nativeable implements EncodedKeyPair, Serializable {

    private static final long serialVersionUID = 6641548573197806280L;

    private final EVP_PKEY pkey;
    private final ASN1Native asn1Native;
    private final EvpNative evpNative;

    /* PKCS8Encoded */
    private final byte[] privateKey;

    /* X509Encoded */
    private final byte[] publicKey;

    public NaitveEncodedKeyPair(
            EVP_PKEY pkey,
            ASN1Native asn1Native,
            EvpNative evpNative,
            byte[] privateKey, byte[] publicKey
    ) {
        super(evpNative);
        this.asn1Native = asn1Native;
        this.pkey = pkey;
        this.evpNative = evpNative;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public PKCS8EncodedKeySpec getPrivatekey() {
        return new PKCS8EncodedKeySpec(privateKey);
    }

    @Override
    public EncryptedPrivateKeyInfo getEncryptedPrivatekey(String algName, byte[] password) throws IOException {
        BIO bio = super.createBIO();
        final int nid = asn1Native.OBJ_sn2nid(algName);
        evpNative.throwOnError(evpNative.i2d_PKCS8PrivateKey_nid_bio(
                bio,
                this.pkey,
                nid,
                password
        ), this);
        final byte[] src = super.readBio(bio);
        return new EncryptedPrivateKeyInfo(src);
    }

    private byte[] pemDecode(byte[] src) {
        final String[] strings = new String(src).split("\n");
        strings[0] = "";
        strings[strings.length - 1] = "";
        return Base64.getDecoder().decode(String.join("", strings));
    }

    @Override
    public X509EncodedKeySpec getPublickey() {
        return new X509EncodedKeySpec(publicKey);
    }
}
