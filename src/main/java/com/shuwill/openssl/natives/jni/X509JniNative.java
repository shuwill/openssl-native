package com.shuwill.openssl.natives.jni;

import java.nio.ByteBuffer;

/**
 * @author shuwei.wang
 * @description:
 */
public class X509JniNative {

    public static native long X509New();

    public static native void X509Free(long x);

    public static native long X509NameNew();

    public static native void X509NameFree(long name);

    public static native int X509NameAddEntryByTxt(long name, String field, int type, ByteBuffer bytes, int len, int loc, int set);

    public static native int X509SetVersion(long x, long version);

    public static native long X509GetVersion(long x);

    public static native int X509SetNotBefore(long x, long tm);

    public static native int X509SetNotAfter(long x, long tm);

    public static native int X509SetSerialNumber(long x, long serial);

    public static native int X509SetSubjectName(long x, long name);

    public static native long X509GetSubjectName(long a);

    public static native int X509SetIssuerName(long x, long name);

    public static native long X509GetIssuerName(long a);

    public static native int X509SetPubkey(long x, long pkey);

    public static native int X509AddExt(long x, long ex, int loc);

    public static native long X509ExtensionNew();

    public static native void X509ExtensionFree(long ex);

    public static native long X509V3ExtNconfNid(int extnid, String value, long issuer, long subject, long req, long crl, int flags);

    public static native long X509V3ExtI2d(int extnid, int crit, long extstruc);

    public static native int X509Sign(long x, long pkey, long md);

    public static native int i2dX509Bio(long bp, long X509);

    public static native long d2iX509Bio(long bp);

    public static native long X509ReqNew();

    public static native void X509ReqFree(long req);

    public static native int X509ReqSetSubjectName(long req, long name);

    public static native long X509ReqGetSubjectName(long req);

    public static native int X509ReqSetPubkey(long x, long pkey);

    public static native int X509ReqSign(long x, long pkey, long md);

    public static native int i2dX509ReqBio(long bp, long req);

    public static native long d2iX509ReqBio(long bp);

    public static native String X509NameOneline(long a);

    public static native int X509Print(long bp, long x);

    public static native long X509GetX509Pubkey(long x);

    public static native int X509PubkeySetParam(long alg, long aobj);
}
