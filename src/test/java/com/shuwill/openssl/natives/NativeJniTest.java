package com.shuwill.openssl.natives;

import com.shuwill.openssl.common.AbstractTest;
import com.shuwill.openssl.natives.jni.ASN1JniNative;
import com.shuwill.openssl.natives.jni.CommonJniNative;
import com.shuwill.openssl.natives.jni.EvpJniNative;
import com.shuwill.openssl.natives.jni.NativeInt;
import com.shuwill.openssl.natives.jni.impl.CommonJniNativeImpl;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;

public class NativeJniTest extends AbstractTest {

    private CommonNative commonNative;

    @Before
    public void loadNativeLibrary() throws IOException {
        System.load(getLibrary(NAITVE_LIBRARY_NAME));
        commonNative = new CommonJniNativeImpl();
    }

    @Test
    public void testBio() {
        final byte[] source = "test".getBytes();

        final long bio_method = CommonJniNative.bioMem();
        final long bio = CommonJniNative.bioNew(bio_method);

        NativeInt written = new NativeInt();
        ByteBuffer dataToW = ByteBuffer.allocateDirect(1024);
        dataToW.put(source);
        final int writeResult = CommonJniNative.bioWriteEx(bio, dataToW, dataToW.position(), written);
        System.out.println("written count: " + written);
        System.out.println("written result: " + writeResult);

        NativeInt readed = new NativeInt();
        ByteBuffer dataToR = ByteBuffer.allocateDirect(1024);
        final int readedResult = CommonJniNative.bioReadEx(bio, dataToR, dataToR.capacity(), readed);
        final byte[] readbytes = new byte[readed.value()];
        dataToR.get(readbytes);
        System.out.println("readed count: " + readed);
        System.out.println("readed result: " + readedResult);
        System.out.println("bio source: " + new String(readbytes));

        CommonJniNative.bioFree(bio);

        final long err = CommonJniNative.errPeekError();
        System.out.println(CommonJniNative.errString(err, null));
    }

    @Test
    public void testAsn1() {
        System.out.println(ASN1JniNative.ln2nid("rsaEncryption"));
        System.out.println(ASN1JniNative.sn2nid("rsaEncryption"));
        final int nid = ASN1JniNative.txt2nid("sm2");
        System.out.println(ASN1JniNative.nid2ln(nid));
        System.out.println(ASN1JniNative.nid2sn(nid));

        final long obj = ASN1JniNative.nid2obj(nid);
        System.out.println(ASN1JniNative.obj2nid(obj));

        final ByteBuffer buf = ByteBuffer.allocateDirect(1024);
        final int len = ASN1JniNative.obj2txt(buf, buf.capacity(), obj, 1);
        buf.position(0);
        byte[] result = new byte[len];
        buf.get(result);
        System.out.println(new String(result));

        ASN1JniNative.asn1ObjectFree(obj);

        final long obj1 = ASN1JniNative.txt2obj("1.2.840.113549.1.1.1", 1);
        System.out.println(ASN1JniNative.cmp(obj, obj1));
        ASN1JniNative.asn1ObjectFree(obj1);
    }

    @Test
    public void testDigest() {
        final long ctx = EvpJniNative.evpMdCtxNew();

        final long sha256 = EvpJniNative.evpGetDigestByName("sha2256");
        System.out.println(EvpJniNative.evpMdGetName(sha256));
        System.out.println(EvpJniNative.evpMdGetDescription(sha256));
        System.out.println(EvpJniNative.evpMdGetSize(sha256));
        EvpJniNative.evpMdFree(sha256);

        final int nid = ASN1JniNative.sn2nid("MD5");
        System.out.println(nid);
        final long md5 = EvpJniNative.evpGetDigestByNid(nid);
        System.out.println(EvpJniNative.evpMdGetName(md5));
        System.out.println(EvpJniNative.evpMdGetSize(md5));
        System.out.println(EvpJniNative.evpMdGetDescription(md5));

        byte[] source = "123".getBytes();
        ByteBuffer buffer = ByteBuffer.allocateDirect(source.length);
        buffer.put(source);
        commonNative.throwOnError(EvpJniNative.evpDigestInit(ctx, md5), () -> {
        });
        commonNative.throwOnError(EvpJniNative.evpDigestUpdate(ctx, buffer, source.length), () -> {
        });

        ByteBuffer outBuffer = ByteBuffer.allocateDirect(1024);
        NativeInt s = new NativeInt();
        commonNative.throwOnError(EvpJniNative.evpDigestFinal(ctx, outBuffer, s), () -> {
        });
        byte[] result = new byte[s.value()];
        outBuffer.get(result);
        System.out.println(Hex.toHexString(result));

        EvpJniNative.evpMdFree(md5);
        EvpJniNative.evpMdCtxFree(ctx);
    }

    @Test
    public void testCipher() {
        final long ctx = EvpJniNative.evpCipherCtxNew();
        final long aes_128_ecb = EvpJniNative.evpGetCipherByName("aes-128-cbc");
        System.out.println(EvpJniNative.evpCipherGetName(aes_128_ecb));
        System.out.println(EvpJniNative.evpCipherGetDescription(aes_128_ecb));
        System.out.println(EvpJniNative.evpCipherGetBlocksize(aes_128_ecb));
        System.out.println(EvpJniNative.evpCipherGetMode(aes_128_ecb));
        System.out.println(EvpJniNative.evpCipherIs(aes_128_ecb, "aes-128-ecb"));

        System.out.println(EvpJniNative.evpCipherGetKeyLength(aes_128_ecb));
        System.out.println(EvpJniNative.evpCipherGetIvLength(aes_128_ecb));
        //System.out.println(EvpJniNative.EVPCIPHERCTXgetkeylength(ctx));
        //System.out.println(EvpJniNative.EVPCIPHERCTXgetivlength(ctx));
        //System.out.println(EvpJniNative.EVPCIPHERCTXsetkeylength(ctx, 16));
        //System.out.println(EvpJniNative.EVPCIPHERCTXsetpadding(ctx, 16));

        byte[] saltBytes = "salt".getBytes();
        ByteBuffer salt = ByteBuffer.allocateDirect(saltBytes.length);
        salt.put(saltBytes);

        byte[] dataBytes = "key".getBytes();
        ByteBuffer data = ByteBuffer.allocateDirect(dataBytes.length);
        data.put(dataBytes);

        final long md = EvpJniNative.evpGetDigestByName("md5");

        final ByteBuffer key = ByteBuffer.allocateDirect(EvpNative.EVP_MAX_KEY_LENGTH);
        final ByteBuffer iv = ByteBuffer.allocateDirect(EvpNative.EVP_MAX_IV_LENGTH);

        System.out.println(EvpJniNative.evpBytesToKey(aes_128_ecb, md, null, data, data.capacity(), 1, key, iv));
        byte[] keyBytes = new byte[EvpJniNative.evpCipherGetKeyLength(aes_128_ecb)];
        byte[] ivBytes = new byte[EvpJniNative.evpCipherGetIvLength(aes_128_ecb)];

        key.get(keyBytes);
        System.out.println(Base64.getEncoder().encodeToString(keyBytes));
        iv.get(ivBytes);
        System.out.println(Base64.getEncoder().encodeToString(ivBytes));

        commonNative.throwOnError(EvpJniNative.evpCipherInit(ctx, aes_128_ecb, key, iv, 1), () -> {
        });

        byte[] source = "source".getBytes();
        ByteBuffer out = ByteBuffer.allocateDirect(8192);
        NativeInt outl = new NativeInt();
        final ByteBuffer in = ByteBuffer.allocateDirect(source.length);
        in.put(source);
        commonNative.throwOnError(EvpJniNative.evpCipherUpdate(ctx, out, outl, in, in.capacity()), () -> {
        });
        commonNative.throwOnError(EvpJniNative.evpCipherFinal(ctx, out, outl), () -> {
        });

        byte[] encReuslt = new byte[outl.value()];
        out.get(encReuslt);
        System.out.println(Base64.getEncoder().encodeToString(encReuslt));

        EvpJniNative.evpCipherFree(aes_128_ecb);
        EvpJniNative.evpCipherCtxFree(ctx);
    }
}
