package com.shuwill.openssl.natives;

import com.shuwill.openssl.common.AbstractTest;
import com.shuwill.openssl.natives.jna.Asn1JnaNative;
import com.shuwill.openssl.natives.jna.EvpJnaNative;
import com.shuwill.openssl.natives.jna.JNA_X509V3_CTX;
import com.shuwill.openssl.natives.jna.X509JnaNative;
import com.shuwill.openssl.natives.jna.impl.CommonJnaNativeImpl;
import com.shuwill.openssl.pem.Pem;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.shuwill.openssl.natives.ASN1Native.MBSTRING_ASC;

public class NativeJnaTest extends AbstractTest {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private EvpJnaNative evpNative;
    private Asn1JnaNative asn1Native;
    private X509JnaNative x509Native;
    private CommonNative commonNative;

    @Before
    public void initEnv() throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        this.evpNative = NativeLibraryLoader.getInstance().load(getLibrary(CRYPTO_LIBRARY_NAME), EvpJnaNative.class);
        this.asn1Native = NativeLibraryLoader.getInstance().load(getLibrary(CRYPTO_LIBRARY_NAME), Asn1JnaNative.class);
        this.x509Native = NativeLibraryLoader.getInstance().load(getLibrary(CRYPTO_LIBRARY_NAME), X509JnaNative.class);
        this.commonNative = new CommonJnaNativeImpl(this.evpNative);
    }

    private Pointer generateRsaEVP_PKEY() {
        final int nid = asn1Native.OBJ_txt2nid("rsaEncryption");
        final Pointer ctx = evpNative.EVP_PKEY_CTX_new_id(nid, null);
        commonNative.throwOnError(evpNative.EVP_PKEY_keygen_init(ctx), () -> {
        });

        evpNative.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

        final Pointer evp_pkey = evpNative.EVP_PKEY_new();
        final PointerByReference p_evp_pkey = new PointerByReference(evp_pkey);
        commonNative.throwOnError(evpNative.EVP_PKEY_generate(ctx, p_evp_pkey), () -> {
            evpNative.EVP_PKEY_free(evp_pkey);
            evpNative.EVP_PKEY_CTX_free(ctx);
        });
        return evp_pkey;
    }

    private Pointer generateECEVP_PKEY() {
        final int nid = asn1Native.OBJ_txt2nid("id-ecPublicKey");
        final Pointer ctx = evpNative.EVP_PKEY_CTX_new_id(nid, null);
        commonNative.throwOnError(evpNative.EVP_PKEY_paramgen_init(ctx), () -> {
        });

        int curve_nid = asn1Native.OBJ_txt2nid("sm2");
        commonNative.throwOnError(evpNative.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid), () -> {
        });
        evpNative.EVP_PKEY_CTX_set_ec_param_enc(ctx, EvpNative.OPENSSL_EC_NAMED_CURVE);

        final Pointer evp_pkey_param = evpNative.EVP_PKEY_new();
        final PointerByReference p_evp_pkey_param = new PointerByReference(evp_pkey_param);
        commonNative.throwOnError(evpNative.EVP_PKEY_paramgen(ctx, p_evp_pkey_param), () -> {
        });

        Pointer key_ctx = evpNative.EVP_PKEY_CTX_new(evp_pkey_param, null);
        commonNative.throwOnError(evpNative.EVP_PKEY_keygen_init(key_ctx), () -> {
        });

        final Pointer evp_pkey = evpNative.EVP_PKEY_new();
        final PointerByReference p_evp_pkey = new PointerByReference(evp_pkey);
        commonNative.throwOnError(evpNative.EVP_PKEY_keygen(key_ctx, p_evp_pkey), () -> {
            evpNative.EVP_PKEY_free(evp_pkey);
            evpNative.EVP_PKEY_CTX_free(ctx);
        });
        return evp_pkey;
    }

    @Test
    public void tesEvpNative() throws Exception {
        final Pointer evp_pkey = this.generateECEVP_PKEY();

        final Pointer pkcs8_priv_key_info = evpNative.EVP_PKEY2PKCS8(evp_pkey);
        Pointer privateBIO = evpNative.BIO_new(evpNative.BIO_s_mem());
        commonNative.throwOnError(evpNative.i2d_PKCS8_PRIV_KEY_INFO_bio(privateBIO, pkcs8_priv_key_info), () -> {
            evpNative.EVP_PKEY_free(evp_pkey);
            evpNative.PKCS8_PRIV_KEY_INFO_free(pkcs8_priv_key_info);
        });

        ByteBuffer privateKeyBuffer = ByteBuffer.allocate(8192);
        final IntBuffer privateReadbytes = IntBuffer.allocate(1);
        evpNative.BIO_read_ex(privateBIO, privateKeyBuffer, privateKeyBuffer.capacity(), privateReadbytes);

        final int privateReadLength = privateReadbytes.get();
        byte[] privateKeyBytes = new byte[privateReadLength];
        privateKeyBuffer.position(0).limit(privateReadLength);
        privateKeyBuffer.get(privateKeyBytes);

        final KeyFactory keyFactory = KeyFactory.getInstance("ec", BouncyCastleProvider.PROVIDER_NAME);
        final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        logger.info("Private key is " + privateKey);

        Pointer publicBIO = evpNative.BIO_new(evpNative.BIO_s_mem());
        commonNative.throwOnError(evpNative.i2d_PUBKEY_bio(publicBIO, evp_pkey), () -> {
        });

        ByteBuffer publicKeyBuffer = ByteBuffer.allocate(8192);
        final IntBuffer publicReadbytes = IntBuffer.allocate(1);
        evpNative.BIO_read_ex(publicBIO, publicKeyBuffer, publicKeyBuffer.capacity(), publicReadbytes);

        final int publicReadLength = publicReadbytes.get();
        byte[] publicKeyBytes = new byte[publicReadLength];
        publicKeyBuffer.position(0).limit(publicReadLength);
        publicKeyBuffer.get(publicKeyBytes);

        final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        logger.info("\n{}", ECUtil.generatePublicKeyParameter(publicKey));
        logger.info("Public key: " + publicKey);
    }

    @Test
    public void testObjIdentifiedNative() {
        final int nid = asn1Native.OBJ_txt2nid("rsaEncryption");
        logger.info(asn1Native.OBJ_nid2sn(nid));

        final Pointer asn1_object = asn1Native.OBJ_nid2obj(nid);
        final ByteBuffer buf = ByteBuffer.allocate(1024);
        final int len = asn1Native.OBJ_obj2txt(buf, buf.capacity(), asn1_object, 1);
        buf.position(0);
        byte[] result = new byte[len];
        buf.get(result);
        logger.info(new String(result));
        asn1Native.ASN1_OBJECT_free(asn1_object);
    }

    @Test
    public void testMakeCert() throws Exception {
        final Pointer x509 = x509Native.X509_new();
        x509Native.X509_set_version(x509, 2);

        final Pointer serialNumber = asn1Native.ASN1_INTEGER_new();
        asn1Native.ASN1_INTEGER_set(serialNumber, System.currentTimeMillis());
        x509Native.X509_set_serialNumber(x509, serialNumber);

        final Pointer not_before = asn1Native.X509_gmtime_adj(null, -100);
        x509Native.X509_set1_notBefore(x509, not_before);
        final Pointer not_after = asn1Native.X509_gmtime_adj(null, 3600);
        x509Native.X509_set1_notAfter(x509, not_after);

        final Pointer subjectname = x509Native.X509_NAME_new();
        x509Native.X509_NAME_add_entry_by_txt(subjectname, "C", MBSTRING_ASC, "CN".getBytes(), 2, -1, 0);
        x509Native.X509_NAME_add_entry_by_txt(subjectname, "ST", MBSTRING_ASC, "SH".getBytes(), 2, -1, 0);
        x509Native.X509_NAME_add_entry_by_txt(subjectname, "O", MBSTRING_ASC, "Some CA organization".getBytes(), 20, -1, 0);
        x509Native.X509_NAME_add_entry_by_txt(subjectname, "CN", MBSTRING_ASC, "ca test".getBytes(), 7, -1, 0);
        x509Native.X509_NAME_add_entry_by_txt(subjectname, "emailAddress", MBSTRING_ASC, "ca test".getBytes(), 7, -1, 0);
        x509Native.X509_set_subject_name(x509, subjectname);

        final Pointer issuername = x509Native.X509_NAME_new();
        x509Native.X509_NAME_add_entry_by_txt(issuername, "C", MBSTRING_ASC, "CN".getBytes(), 2, -1, 0);
        x509Native.X509_NAME_add_entry_by_txt(issuername, "ST", MBSTRING_ASC, "SH".getBytes(), 2, -1, 0);
        x509Native.X509_NAME_add_entry_by_txt(issuername, "O", MBSTRING_ASC, "Some CA organization".getBytes(), 20, -1, 0);
        x509Native.X509_NAME_add_entry_by_txt(issuername, "CN", MBSTRING_ASC, "ca test".getBytes(), 7, -1, 0);
        x509Native.X509_set_issuer_name(x509, issuername);

        // extension
        // BasicConstraints
        String basicConstraints = "critical,CA:true,pathlen:1";
        final int basicConstraintsNid = asn1Native.OBJ_txt2nid("basicConstraints");
        this.appendX509Extension(x509, basicConstraintsNid, basicConstraints);
        // KeyUsage
        String KeyUsage = "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign,encipherOnly,decipherOnly";
        final int KeyUsageNid = asn1Native.OBJ_txt2nid("keyUsage");
        this.appendX509Extension(x509, KeyUsageNid, KeyUsage);
        // SubjectKeyIdentifier
        String subjectKeyIdentifier = "hash";
        final int subjectKeyIdentifierNid = asn1Native.OBJ_txt2nid("subjectKeyIdentifier");
        this.appendX509Extension(x509, subjectKeyIdentifierNid, subjectKeyIdentifier);
        // AuthorityKeyIdentifier
        String authorityKeyIdentifier = "critical,keyid:always,issuer:always";
        final int authorityKeyIdentifierNid = asn1Native.OBJ_txt2nid("authorityKeyIdentifier");
        this.appendX509Extension(x509, authorityKeyIdentifierNid, authorityKeyIdentifier);
        // ExtendedKeyUsage
        String extendedKeyUsage = "critical,serverAuth,clientAuth,codeSigning,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC";
        final int extendedKeyUsageNid = asn1Native.OBJ_txt2nid("extendedKeyUsage");
        this.appendX509Extension(x509, extendedKeyUsageNid, extendedKeyUsage);

        final Pointer pkey = generateRsaEVP_PKEY();
        x509Native.X509_set_pubkey(x509, pkey);

        x509Native.X509_sign(x509, pkey, evpNative.EVP_get_digestbyname("sha256"));
        final Pointer bio = x509Native.BIO_new(x509Native.BIO_s_mem());
        x509Native.i2d_X509_bio(bio, x509);

        ByteBuffer certBuffer = ByteBuffer.allocate(8192);
        IntBuffer readbytes = IntBuffer.allocate(1);
        x509Native.BIO_read_ex(bio, certBuffer, certBuffer.capacity(), readbytes);
        byte[] certBytes = new byte[readbytes.get()];
        certBuffer.get(certBytes);
        logger.info(Base64.getEncoder().encodeToString(certBytes));
        try (final OutputStream out = Files.newOutputStream(Paths.get("openssl-jna-created.crt"))){
            Pem.write(out, Pem.PEM_STRING_X509, certBytes);
        }

        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        final Principal subjectDN = certificate.getSubjectDN();
        logger.info("" + subjectDN);
        logger.info("\n{}", certificate.getPublicKey());

        x509Native.X509_free(x509);
    }

    private void appendX509Extension(Pointer x509, int nid, String value) {
        final JNA_X509V3_CTX x509V3_ctx = new JNA_X509V3_CTX();
        x509Native.X509V3_set_ctx(x509V3_ctx, x509, x509, null, null, 0);
        final Pointer extension = x509Native.X509V3_EXT_nconf_nid(null, x509V3_ctx, nid, value);
        commonNative.throwOnError(x509Native.X509_add_ext(x509, extension, -1), () -> {
        });
    }
}
