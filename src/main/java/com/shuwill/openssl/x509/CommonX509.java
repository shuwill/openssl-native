package com.shuwill.openssl.x509;

import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.Nativeable;
import com.shuwill.openssl.natives.X509Native;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.BIO_METHOD;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.PKCS8_PRIV_KEY_INFO;
import com.shuwill.openssl.natives.pointer.X509;
import com.shuwill.openssl.natives.pointer.X509_NAME;
import com.shuwill.openssl.natives.pointer.X509_PUBKEY;

import java.nio.IntBuffer;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class CommonX509 extends Nativeable {

    protected static final int X509_BUFFER_SIZE = 8192;

    protected final EvpNative evpNative;
    protected final X509Native x509Native;
    protected final ASN1Native asn1Native;

    protected CommonX509(EvpNative evpNative, X509Native x509Native, ASN1Native asn1Native) {
        super(evpNative);
        this.evpNative = evpNative;
        this.x509Native = x509Native;
        this.asn1Native = asn1Native;
    }

    protected EVP_PKEY getPublicKey(byte[] publicKey) {
        final BIO_METHOD biom = x509Native.throwOnError(x509Native::BIO_s_mem, this);
        BIO publicKeyBio = x509Native.throwOnError(() -> x509Native.BIO_new(biom), this);
        x509Native.BIO_write(publicKeyBio, publicKey, publicKey.length);
        return evpNative.d2i_PUBKEY_bio(publicKeyBio);
    }

    protected X509EncodedKeySpec getPublickey(EVP_PKEY pkey) {
        BIO bio = this.createBIO();
        this.evpNative.throwOnError(evpNative.i2d_PUBKEY_bio(bio, pkey), this);
        byte[] buffer = new byte[X509_BUFFER_SIZE];
        final IntBuffer readbytes = IntBuffer.allocate(1);
        evpNative.BIO_read_ex(bio, buffer, buffer.length, readbytes);

        final int length = readbytes.get();
        byte[] publicKey = new byte[length];
        System.arraycopy(buffer, 0, publicKey, 0, length);
        return new X509EncodedKeySpec(publicKey);
    }

    protected void setPublicKeyAlgorithm(X509 x509, String publicKeyAlgorithm) {
        if(publicKeyAlgorithm != null && !publicKeyAlgorithm.isEmpty()) {
            final X509_PUBKEY x509_pubkey = x509Native.X509_get_X509_PUBKEY(x509);
            final int pubkey_algor_nid = asn1Native.OBJ_sn2nid(publicKeyAlgorithm);
            final ASN1_OBJECT pubkey_algor_oid = asn1Native.OBJ_nid2obj(pubkey_algor_nid);
            x509Native.throwOnError(x509Native.X509_PUBKEY_set_param(x509_pubkey, pubkey_algor_oid), this);
        }
    }

    protected EVP_PKEY getPrivateKey(byte[] privateKey) {
        BIO privateKeyBio = x509Native.throwOnError(() -> x509Native.BIO_new(x509Native.BIO_s_mem()), this);
        x509Native.BIO_write(privateKeyBio, privateKey, privateKey.length);
        PKCS8_PRIV_KEY_INFO pkcs8_priv_key_info = evpNative.throwOnError(() -> evpNative.d2i_PKCS8_PRIV_KEY_INFO_bio(privateKeyBio), this);
        return evpNative.EVP_PKCS82PKEY(pkcs8_priv_key_info);
    }

    protected List<X509Attribute> getX509Attributes(X509_NAME x509_name) {
        final String nameline = x509Native.X509_NAME_oneline(x509_name);
        List<X509Attribute> x509Attributes = new ArrayList<>();
        if(nameline != null && !nameline.isEmpty()) {
            final String[] nameFragments = nameline.split("/");
            for (String nameFragment : nameFragments) {
                final String[] namePair = nameFragment.split("=");
                if(namePair.length == 2) {
                    final X509AttributeType x509AttributeType = X509AttributeType.get(namePair[0]);
                    if(x509AttributeType != null) {
                        x509Attributes.add(new X509Attribute(x509AttributeType, namePair[1]));
                    }
                }
            }
        }
        return x509Attributes;
    }
}
