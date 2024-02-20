package com.shuwill.openssl.x509;

import com.shuwill.openssl.common.OpensslNativeEnvironment;
import com.shuwill.openssl.natives.ASN1Native;
import com.shuwill.openssl.natives.EvpNative;
import com.shuwill.openssl.natives.X509Native;
import com.shuwill.openssl.natives.pointer.ASN1_INTEGER;
import com.shuwill.openssl.natives.pointer.ASN1_TIME;
import com.shuwill.openssl.natives.pointer.BIO;
import com.shuwill.openssl.natives.pointer.EVP_PKEY;
import com.shuwill.openssl.natives.pointer.X509V3_CTX;
import com.shuwill.openssl.natives.pointer.X509_EXTENSION;
import com.shuwill.openssl.natives.pointer.X509_NAME;
import com.shuwill.openssl.pem.Pem;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

public class NativeX509 extends CommonX509 implements X509, Serializable {

    private static final long serialVersionUID = 3752739192465019494L;

    private int version;
    private long serialNumber;
    private Calendar notBefore;
    private Calendar notAfter;
    private List<X509Attribute> subject;
    private List<X509Attribute> issuer;
    private X509EncodedKeySpec publickey;
    private PKCS8EncodedKeySpec signPrivatekey;
    private String digestAlgorithm;
    private String publicKeyAlgorithm;
    private BasicConstraints basicConstraints = BasicConstraints.builder().build();
    private SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.builder().build();
    private AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.builder().build();
    private KeyUsage keyUsage = KeyUsage.builder().build();

    private byte[] encoded;
    private com.shuwill.openssl.natives.pointer.X509 x509;
    
    @Override
    public int getVersion() {
        return version;
    }

    @Override
    public long getSerialNumber() {
        return serialNumber;
    }

    @Override
    public Calendar getNotBefore() {
        return notBefore;
    }

    @Override
    public Calendar getNotAfter() {
        return notAfter;
    }

    @Override
    public List<X509Attribute> getSubject() {
        return subject;
    }

    @Override
    public List<X509Attribute> getIssuer() {
        return issuer;
    }

    @Override
    public X509EncodedKeySpec getPublickey() {
        return this.publickey;
    }

    @Override
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    @Override
    public BasicConstraints getBasicConstraints() {
        return basicConstraints;
    }

    @Override
    public SubjectKeyIdentifier getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    @Override
    public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    @Override
    public KeyUsage getKeyUsage() {
        return keyUsage;
    }

    public byte[] getEncoded() {
        return encoded;
    }


    protected NativeX509(X509Native x509Native, EvpNative evpNative, ASN1Native asn1Native) {
        super(evpNative, x509Native, asn1Native);
    }

    public byte[] encode() {
        this.x509 = x509Native.throwOnError(x509Native::X509_new, this);
        // set version
        x509Native.throwOnError(x509Native.X509_set_version(this.x509, version), this);
        // set serialNumber
        ASN1_INTEGER serialNumber_asn1 = asn1Native.throwOnError(asn1Native::ASN1_INTEGER_new, this);
        x509Native.throwOnError(asn1Native.ASN1_INTEGER_set(serialNumber_asn1, serialNumber), this);
        x509Native.throwOnError(x509Native.X509_set_serialNumber(this.x509, serialNumber_asn1), this);
        // set notbefore
        Instant now = Instant.now();
        final long beforeAdj = this.notBefore.toInstant().getEpochSecond() - now.getEpochSecond();
        ASN1_TIME notbefore_asn1 = asn1Native.throwOnError(() -> asn1Native.X509_gmtime_adj(beforeAdj), this);
        x509Native.throwOnError(x509Native.X509_set_notBefore(this.x509, notbefore_asn1), this);
        // set notafter
        final long afterAdj = this.notAfter.toInstant().getEpochSecond() - now.getEpochSecond();
        ASN1_TIME notafter_asn1 = asn1Native.throwOnError(() -> asn1Native.X509_gmtime_adj(afterAdj), this);
        x509Native.throwOnError(x509Native.X509_set_notAfter(this.x509, notafter_asn1), this);
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
        x509Native.throwOnError(x509Native.X509_set_subject_name(this.x509, subject_x509_name), this);
        // set issuername
        X509_NAME issuer_x509_name = x509Native.throwOnError(x509Native::X509_NAME_new, this);
        for (X509Attribute x509Attribute : issuer) {
            final byte[] valueBytes = x509Attribute.getValue().getBytes(StandardCharsets.UTF_8);
            x509Native.throwOnError(x509Native.X509_NAME_add_entry_by_txt(
                    issuer_x509_name,
                    x509Attribute.getType().name(),
                    valueBytes
            ), this);
        }
        x509Native.throwOnError(x509Native.X509_set_issuer_name(this.x509, issuer_x509_name), this);
        // set basicConstraints
        this.apendExtersion(this.x509, basicConstraints);
        // set keyUsage
        this.apendExtersion(this.x509, keyUsage);
        // set subjectKeyIdentifier
        this.apendExtersion(this.x509, subjectKeyIdentifier);
        // set authorityKeyIdentifier
        this.apendExtersion(this.x509, authorityKeyIdentifier);
        // set publickey
        final EVP_PKEY publickey = super.getPublicKey(this.publickey.getEncoded());
        x509Native.throwOnError(x509Native.X509_set_pubkey(this.x509, publickey), this);
        // sign
        final EVP_PKEY privateKey = super.getPrivateKey(this.signPrivatekey.getEncoded());
        x509Native.throwOnError(
                code -> code != 0,
                x509Native.X509_sign(this.x509, privateKey, evpNative.EVP_get_digestbyname(this.digestAlgorithm)),
                this
        );

        super.setPublicKeyAlgorithm(x509, this.publicKeyAlgorithm);

        final BIO bio = super.createBIO();
        x509Native.throwOnError(x509Native.i2d_X509_bio(bio, this.x509), this);

        byte[] certBuffer = new byte[X509_BUFFER_SIZE];
        IntBuffer readbytes = IntBuffer.allocate(1);
        x509Native.BIO_read_ex(bio, certBuffer, certBuffer.length, readbytes);
        this.encoded = new byte[readbytes.get()];
        System.arraycopy(certBuffer, 0, this.encoded, 0, this.encoded.length);

        return this.encoded;
    }

    private void apendExtersion(com.shuwill.openssl.natives.pointer.X509 x509, Extension extension) {
        String value = extension.toString();
        if (value == null || value.isEmpty()) {
            return;
        }
        final int nid = asn1Native.OBJ_txt2nid(extension.getId());
        final X509V3_CTX x509V3_ctx = new X509V3_CTX();
        ExtensionContext extensionContext = extension.getExtensionContext();
        if (extensionContext != null) {
            x509V3_ctx.setFlags(extensionContext.getFlags());
            if (extensionContext.getIssuerCert() != null) {
                x509V3_ctx.setIssuer_cert(this.toPointerX509(extensionContext.getIssuerCert()));
            } else if(extensionContext.isIssuerSelf()){
                x509V3_ctx.setIssuer_cert(x509);
            }
            if (extensionContext.getSubjectCert() != null) {
                x509V3_ctx.setSubject_cert(this.toPointerX509(extensionContext.getSubjectCert()));
            } else if (extensionContext.isSubjectSelf()){
                x509V3_ctx.setSubject_cert(x509);
            }
        }
        final X509_EXTENSION x509_extension = x509Native.throwOnError(
                () -> x509Native.X509V3_EXT_nconf_nid(x509V3_ctx, nid, value),
                this
        );
        x509Native.throwOnError(x509Native.X509_add_ext(x509, x509_extension, -1), this);
    }

    @Override
    public String print() {
        final BIO bio = super.createBIO();
        x509Native.throwOnError(x509Native.X509_print(bio, x509), this);
        return new String(readBio(bio));
    }

    @Override
    public void parse() {
        BIO bio = super.createBIO();
        x509Native.BIO_write(bio, this.encoded, this.encoded.length);
        this.x509 = x509Native.throwOnError(() -> x509Native.d2i_X509_bio(bio), this);

        this.version = (int) x509Native.X509_get_version(this.x509);

        final X509_NAME x509_subject_name = x509Native.X509_get_subject_name(this.x509);
        this.subject = super.getX509Attributes(x509_subject_name);

        final X509_NAME x509_issuer_name = x509Native.X509_get_issuer_name(this.x509);
        this.issuer = super.getX509Attributes(x509_issuer_name);

        final EVP_PKEY pkey = evpNative.X509_get_pubkey(this.x509);
        this.publickey = super.getPublickey(pkey);
    }

    private com.shuwill.openssl.natives.pointer.X509 toPointerX509(X509 cert) {
        if(cert instanceof NativeX509) {
            return ((NativeX509) cert).x509;
        }
        final byte[] content = cert.getEncoded();
        final BIO bio = super.createBIO();
        x509Native.BIO_write(bio, content, content.length);
        return x509Native.throwOnError(() -> x509Native.d2i_X509_bio(bio), this);
    }

    public static NativeX509Builder builder() {
        return new NativeX509Builder();
    }

    public static class NativeX509Builder {

        private int _version;
        private long _serialNumber;
        private Calendar _notBefore;
        private Calendar _notAfter;
        private List<X509Attribute> _subject = new ArrayList<>();
        private List<X509Attribute> _issuer = new ArrayList<>();
        private X509EncodedKeySpec _publickey;
        private PKCS8EncodedKeySpec _signPrivatekey;
        private String _digestAlgorithm;
        private String _publicKeyAlgorithm;
        private BasicConstraints _basicConstraints = BasicConstraints.builder().build();
        private SubjectKeyIdentifier _subjectKeyIdentifier = SubjectKeyIdentifier.builder().build();
        private AuthorityKeyIdentifier _authorityKeyIdentifier = AuthorityKeyIdentifier.builder().build();
        private KeyUsage _keyUsage = KeyUsage.builder().build();

        private byte[] _encoded;

        public NativeX509Builder version(int version) {
            this._version = version;
            return this;
        }

        public NativeX509Builder serialNumber(long serialNumber) {
            this._serialNumber = serialNumber;
            return this;
        }

        public NativeX509Builder notBefore(Calendar notBefore) {
            this._notBefore = notBefore;
            return this;
        }

        public NativeX509Builder notAfter(Calendar notAfter) {
            this._notAfter = notAfter;
            return this;
        }

        public NativeX509Builder subject(List<X509Attribute> subject) {
            this._subject = subject;
            return this;
        }

        public NativeX509Builder appendSubject(X509AttributeType type, String value) {
            final X509Attribute x509Attribute = new X509Attribute(type, value);
            this._subject.add(x509Attribute);
            return this;
        }

        public NativeX509Builder issuer(List<X509Attribute> issuer) {
            this._issuer = issuer;
            return this;
        }

        public NativeX509Builder appendIssuer(X509AttributeType type, String value) {
            final X509Attribute x509Attribute = new X509Attribute(type, value);
            this._issuer.add(x509Attribute);
            return this;
        }

        public NativeX509Builder publickey(X509EncodedKeySpec publickey) {
            this._publickey = publickey;
            return this;
        }

        public NativeX509Builder signPrivatekey(PKCS8EncodedKeySpec signPrivatekey) {
            this._signPrivatekey = signPrivatekey;
            return this;
        }

        public NativeX509Builder digestAlgorithm(String digestAlgorithm) {
            this._digestAlgorithm = digestAlgorithm;
            return this;
        }

        public NativeX509Builder publicKeyAlgorithm(String publicKeyAlgorithm) {
            this._publicKeyAlgorithm = publicKeyAlgorithm;
            return this;
        }

        public NativeX509Builder basicConstraints(BasicConstraints basicConstraints) {
            this._basicConstraints = basicConstraints;
            return this;
        }

        public NativeX509Builder subjectKeyIdentifier(SubjectKeyIdentifier subjectKeyIdentifier) {
            this._subjectKeyIdentifier = subjectKeyIdentifier;
            return this;
        }

        public NativeX509Builder authorityKeyIdentifier(AuthorityKeyIdentifier authorityKeyIdentifier) {
            this._authorityKeyIdentifier = authorityKeyIdentifier;
            return this;
        }

        public NativeX509Builder keyUsage(KeyUsage keyUsage) {
            this._keyUsage = keyUsage;
            return this;
        }

        public NativeX509Builder encoded(byte[] encoded) {
            this._encoded = encoded;
            return this;
        }

        public NativeX509Builder pem(InputStream in) throws IOException {
            this._encoded = Pem.read(in);
            return this;
        }

        public NativeX509 build() {
            final OpensslNativeEnvironment opensslEnv = OpensslNativeEnvironment.get();
            final NativeX509 nativeX509 = new NativeX509(
                    opensslEnv.getNativeInterface(X509Native.class),
                    opensslEnv.getNativeInterface(EvpNative.class),
                    opensslEnv.getNativeInterface(ASN1Native.class)
            );
            nativeX509.version = this._version;
            nativeX509.serialNumber = this._serialNumber;
            nativeX509.notBefore = this._notBefore;
            nativeX509.notAfter = this._notAfter;
            nativeX509.subject = this._subject;
            nativeX509.issuer = this._issuer;
            nativeX509.publickey = this._publickey;
            nativeX509.signPrivatekey = this._signPrivatekey;
            nativeX509.digestAlgorithm = this._digestAlgorithm;
            nativeX509.publicKeyAlgorithm = this._publicKeyAlgorithm;
            nativeX509.basicConstraints = this._basicConstraints;
            nativeX509.subjectKeyIdentifier = this._subjectKeyIdentifier;
            nativeX509.authorityKeyIdentifier = this._authorityKeyIdentifier;
            nativeX509.keyUsage = this._keyUsage;
            nativeX509.encoded = this._encoded;
            return nativeX509;
        }

    }
}
