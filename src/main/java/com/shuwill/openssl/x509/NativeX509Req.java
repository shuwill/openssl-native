package com.shuwill.openssl.x509;

import com.shuwill.openssl.common.OpensslNativeEnvironment;
import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.X509Native;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.X509_NAME;
import com.shuwill.openssl.natives.pointer.X509_REQ;

import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class NativeX509Req extends CommonX509 implements X509Req {

    private X509EncodedKeySpec publickey;
    private PKCS8EncodedKeySpec privatekey;
    private String digestAlgorithm;
    private List<X509Attribute> subject;

    private byte[] encoded;

    @Override
    public List<X509Attribute> getSubject() {
        return this.subject;
    }

    @Override
    public X509EncodedKeySpec getPublickey() {
        return this.publickey;
    }

    @Override
    public String getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    protected NativeX509Req(X509Native x509Native, EvpNative evpNative, ASN1Native asn1Native) {
        super(evpNative, x509Native, asn1Native);
    }

    @Override
    public byte[] encode() {
        final com.shuwill.openssl.natives.pointer.X509_REQ x509_req = x509Native.throwOnError(x509Native::X509_REQ_new, this);
        // set subjectname
        X509_NAME subject_x509_name = x509Native.throwOnError(x509Native::X509_NAME_new, this);
        for (X509Attribute x509Attribute : subject) {
            final byte[] valueBytes = x509Attribute.getValue().getBytes(StandardCharsets.UTF_8);
            x509Native.throwOnError(x509Native.X509_NAME_add_entry_by_txt(
                    subject_x509_name,
                    x509Attribute.getType().name(),
                    valueBytes
            ), this);
        }
        x509Native.throwOnError(x509Native.X509_REQ_set_subject_name(x509_req, subject_x509_name), this);
        // set publickey
        final EVP_PKEY publickey = super.getPublicKey(this.publickey.getEncoded());
        x509Native.throwOnError(x509Native.X509_REQ_set_pubkey(x509_req, publickey), this);
        // sign
        final EVP_PKEY privateKey = super.getPrivateKey(this.privatekey.getEncoded());
        x509Native.throwOnError(
                code -> code != 0,
                x509Native.X509_REQ_sign(x509_req, privateKey, evpNative.EVP_get_digestbyname(this.digestAlgorithm)),
                this
        );

        BIO bio = super.createBIO();
        x509Native.throwOnError(x509Native.i2d_X509_REQ_bio(bio, x509_req), this);

        byte[] reqBuffer = new byte[X509_BUFFER_SIZE];
        IntBuffer readbytes = IntBuffer.allocate(1);
        x509Native.BIO_read_ex(bio, reqBuffer, reqBuffer.length, readbytes);
        byte[] encoded = new byte[readbytes.get()];
        System.arraycopy(reqBuffer, 0, encoded, 0, encoded.length);

        return encoded;
    }

    public void parse() {
        BIO bio = super.createBIO();
        x509Native.BIO_write(bio, this.encoded, this.encoded.length);
        final X509_REQ x509_req = x509Native.throwOnError(() -> x509Native.d2i_X509_REQ_bio(bio), this);

        final EVP_PKEY pkey = evpNative.X509_REQ_get_pubkey(x509_req);
        this.publickey = this.getPublickey(pkey);

        final X509_NAME x509_name = x509Native.X509_REQ_get_subject_name(x509_req);
        this.subject = super.getX509Attributes(x509_name);
    }

    public static NativeX509ReqBuilder builder() {
        return new NativeX509ReqBuilder();
    }

    public static class NativeX509ReqBuilder {

        private X509EncodedKeySpec _publickey;
        private PKCS8EncodedKeySpec _privatekey;
        private String _digestAlgorithm;
        private final List<X509Attribute> _subject = new ArrayList<>();

        private byte[] _encoded;

        public NativeX509ReqBuilder publickey(X509EncodedKeySpec publickey) {
            this._publickey = publickey;
            return this;
        }

        public NativeX509ReqBuilder privatekey(PKCS8EncodedKeySpec privatekey) {
            this._privatekey = privatekey;
            return this;
        }

        public NativeX509ReqBuilder digestAlgorithm(String digestAlgorithm) {
            this._digestAlgorithm = digestAlgorithm;
            return this;
        }

        public NativeX509ReqBuilder appendSubject(X509AttributeType type, String value) {
            final X509Attribute x509Attribute = new X509Attribute(type, value);
            this._subject.add(x509Attribute);
            return this;
        }

        public NativeX509ReqBuilder encoded(byte[] encoded) {
            this._encoded = encoded;
            return this;
        }

        public NativeX509Req build() {
            final OpensslNativeEnvironment opensslEnv = OpensslNativeEnvironment.get();
            final NativeX509Req nativeX509Req = new NativeX509Req(
                    opensslEnv.getNativeInterface(X509Native.class),
                    opensslEnv.getNativeInterface(EvpNative.class),
                    opensslEnv.getNativeInterface(ASN1Native.class)
            );
            nativeX509Req.publickey = this._publickey;
            nativeX509Req.privatekey = this._privatekey;
            nativeX509Req.digestAlgorithm = this._digestAlgorithm;
            nativeX509Req.subject = this._subject;
            nativeX509Req.encoded = this._encoded;
            return nativeX509Req;
        }
    }
}
