package com.shuwill.openssl.digest;

import com.shuwill.openssl.common.AbstractTest;
import com.shuwill.openssl.common.IOUtil;
import com.shuwill.openssl.common.OpensslNativeEnvironment;
import com.shuwill.openssl.common.SizeUnit;
import com.shuwill.openssl.common.StopWatch;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class DigestTest extends AbstractTest {
    
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private StopWatch stopWatch;
    private Path testFilePath;

    @Before
    public void initTestEnv() throws IOException {
        OpensslNativeEnvironment.init().useJni(getLibrary(NAITVE_LIBRARY_NAME), getLibrary(CRYPTO_LIBRARY_NAME));
        final int fileSize = 10;
        final SizeUnit sizeUnit = SizeUnit.MB;
        this.stopWatch = new StopWatch();
        this.stopWatch.start("create " + fileSize + sizeUnit + " test file");
        this.testFilePath = IOUtil.createRandomFile(fileSize, sizeUnit);
        this.stopWatch.stop();
    }

    @Test
    public void testNativeDigest() throws Exception {
        try (final Digest digest = NativeDigest.getInstance("sm3");
             final InputStream source = Files.newInputStream(this.testFilePath)) {
            this.stopWatch.start("openssl sm3 digest");
            final byte[] opensslDigestResult = digestByOpenssl(digest, source);
            this.stopWatch.stop();
            logger.info("The openssl sm3 digest result is " + Hex.toHexString(opensslDigestResult));
        }
    }

    @Test
    public void testMd5() throws Exception {
        final byte[] opensslDigestResult;
        try (final Digest opensslDigest = NativeDigest.getInstance("md5");
             final InputStream source = Files.newInputStream(this.testFilePath)) {
            this.stopWatch.start("openssl md5 digest");
            opensslDigestResult = digestByOpenssl(opensslDigest, source);
            this.stopWatch.stop();
            logger.info("The openssl md5 digest result is " + Hex.toHexString(opensslDigestResult));
        }

        final byte[] bcDigestResult;
        try (final InputStream source = Files.newInputStream(this.testFilePath)) {
            org.bouncycastle.crypto.Digest bcDigest = new MD5Digest();
            this.stopWatch.start("bouncycastle md5 digest");
            bcDigestResult = digestByBouncycastle(bcDigest, source);
            this.stopWatch.stop();
            logger.info("The bouncycastle md5 digest result is " + Hex.toHexString(bcDigestResult));
        }

        Assert.assertArrayEquals(opensslDigestResult, bcDigestResult);
        logger.info(this.stopWatch.prettyPrint());
    }

    @Test
    public void testSha1() throws Exception {
        final byte[] opensslDigestResult;
        try (final Digest opensslDigest = NativeDigest.getInstance("sha1");
             final InputStream source = Files.newInputStream(this.testFilePath)) {
            this.stopWatch.start("openssl sha1 digest");
            opensslDigestResult = digestByOpenssl(opensslDigest, source);
            this.stopWatch.stop();
            logger.info("The openssl sha1 digest result is " + Hex.toHexString(opensslDigestResult));
        }

        final byte[] bcDigestResult;
        try (final InputStream source = Files.newInputStream(this.testFilePath)) {
            org.bouncycastle.crypto.Digest bcDigest = new SHA1Digest();
            this.stopWatch.start("bouncycastle sha1 digest");
            bcDigestResult = digestByBouncycastle(bcDigest, source);
            this.stopWatch.stop();
            logger.info("The bouncycastle sha1 digest result is " + Hex.toHexString(bcDigestResult));
        }

        Assert.assertArrayEquals(opensslDigestResult, bcDigestResult);
        logger.info(this.stopWatch.prettyPrint());
    }

    @Test
    public void testSha224() throws Exception {
        final byte[] opensslDigestResult;
        try (final Digest opensslDigest = NativeDigest.getInstance("Sha224");
             final InputStream source = Files.newInputStream(this.testFilePath)) {
            this.stopWatch.start("openssl sha224 digest");
            opensslDigestResult = digestByOpenssl(opensslDigest, source);
            this.stopWatch.stop();
            logger.info("The openssl sha224 digest result is " + Hex.toHexString(opensslDigestResult));
        }

        final byte[] bcDigestResult;
        try (final InputStream source = Files.newInputStream(this.testFilePath)) {
            org.bouncycastle.crypto.Digest bcDigest = new SHA224Digest();
            this.stopWatch.start("bouncycastle sha224 digest");
            bcDigestResult = digestByBouncycastle(bcDigest, source);
            this.stopWatch.stop();
            logger.info("The bouncycastle sha224 digest result is " + Hex.toHexString(bcDigestResult));
        }

        Assert.assertArrayEquals(opensslDigestResult, bcDigestResult);
        logger.info(this.stopWatch.prettyPrint());
    }

    @Test
    public void testSha256() throws Exception {
        final byte[] opensslDigestResult;
        try (final Digest opensslDigest = NativeDigest.getInstance("Sha256");
             final InputStream source = Files.newInputStream(this.testFilePath)) {
            this.stopWatch.start("openssl sha256 digest");
            opensslDigestResult = digestByOpenssl(opensslDigest, source);
            this.stopWatch.stop();
            logger.info("The openssl sha256 digest result is " + Hex.toHexString(opensslDigestResult));
        }

        final byte[] bcDigestResult;
        try (final InputStream source = Files.newInputStream(this.testFilePath)) {
            org.bouncycastle.crypto.Digest bcDigest = new SHA256Digest();
            this.stopWatch.start("bouncycastle sha256 digest");
            bcDigestResult = digestByBouncycastle(bcDigest, source);
            this.stopWatch.stop();
            logger.info("The bouncycastle sha256 digest result is " + Hex.toHexString(bcDigestResult));
        }

        Assert.assertArrayEquals(opensslDigestResult, bcDigestResult);
        logger.info(this.stopWatch.prettyPrint());
    }

    @Test
    public void testSha384() throws Exception {
        final byte[] opensslDigestResult;
        try (final Digest opensslDigest = NativeDigest.getInstance("Sha384");
             final InputStream source = Files.newInputStream(this.testFilePath)) {
            this.stopWatch.start("openssl sha384 digest");
            opensslDigestResult = digestByOpenssl(opensslDigest, source);
            this.stopWatch.stop();
            logger.info("The openssl sha384 digest result is " + Hex.toHexString(opensslDigestResult));
        }

        final byte[] bcDigestResult;
        try (final InputStream source = Files.newInputStream(this.testFilePath)) {
            org.bouncycastle.crypto.Digest bcDigest = new SHA384Digest();
            this.stopWatch.start("bouncycastle sha384 digest");
            bcDigestResult = digestByBouncycastle(bcDigest, source);
            this.stopWatch.stop();
            logger.info("The bouncycastle sha384 digest result is " + Hex.toHexString(bcDigestResult));
        }

        Assert.assertArrayEquals(opensslDigestResult, bcDigestResult);
        logger.info(this.stopWatch.prettyPrint());
    }

    @Test
    public void testSha512() throws Exception {
        final byte[] opensslDigestResult;
        try (final Digest opensslDigest = NativeDigest.getInstance("Sha512");
             final InputStream source = Files.newInputStream(this.testFilePath)) {
            this.stopWatch.start("openssl sha512 digest");
            opensslDigestResult = digestByOpenssl(opensslDigest, source);
            this.stopWatch.stop();
            logger.info("The openssl sha512 digest result is " + Hex.toHexString(opensslDigestResult));
        }

        final byte[] bcDigestResult;
        try (final InputStream source = Files.newInputStream(this.testFilePath)) {
            org.bouncycastle.crypto.Digest bcDigest = new SHA512Digest();
            this.stopWatch.start("bouncycastle sha512 digest");
            bcDigestResult = digestByBouncycastle(bcDigest, source);
            this.stopWatch.stop();
            logger.info("The bouncycastle sha512 digest result is " + Hex.toHexString(bcDigestResult));
        }

        Assert.assertArrayEquals(opensslDigestResult, bcDigestResult);
        logger.info(this.stopWatch.prettyPrint());
    }

    @After
    public void destroyTestEnv() throws IOException {
        Files.deleteIfExists(this.testFilePath);
    }

    private byte[] digestByOpenssl(Digest digest, InputStream source) throws IOException {
        byte[] buffer = new byte[IOUtil.BUFFER_SIZE];
        int len;
        while ((len = source.read(buffer)) != -1) {
            digest.update(buffer, 0, len);
        }
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result);
        return result;
    }

    private byte[] digestByBouncycastle(org.bouncycastle.crypto.Digest digest, InputStream source) throws IOException {
        byte[] buffer = new byte[IOUtil.BUFFER_SIZE];
        int len;
        while ((len = source.read(buffer)) != -1) {
            digest.update(buffer, 0, len);
        }
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }
}
