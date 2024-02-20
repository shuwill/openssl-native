package com.shuwill.openssl.natives.jni;

import java.nio.ByteBuffer;

public class ASN1JniNative extends CommonJniNative {

   public static native long nid2obj(int n);

   public static native String nid2ln(int n);

   public static native String nid2sn(int n);

   public static native int obj2nid(long o);

   public static native int ln2nid(String s);

   public static native int sn2nid(String s);
   
   public static native int txt2nid(String s);

   public static native long txt2obj(String s, int no_name);

   public static native int obj2txt(ByteBuffer buf, int buf_len, long a, int no_name);

   public static native int cmp(long a, long b);

   public static native long asn1ObjectNew();

   public static native void asn1ObjectFree(long a);

   public static native long asn1TimeNew();

   public static native int asn1TimeSetString(long time, String str);

   public static native long X509GmtimeAdj(long s, long adj);

   public static native void asn1TimeFree(long time);

   public static native long asn1IntegerNew();

   public static native int asn1IntegerSet(long a, long v);

   public static native void asn1IntegerFree(long a);

   public static native long asn1OctetStringNew();

   public static native int asn1OctetStringSet(long str, ByteBuffer data, int len);

   public static native void asn1OctetStringFree(long str);

   public static native long X509GetNotBefore(long x);

   public static native long X509GetNotAfter(long x);

   public static native long X509GetSerialNumber(long x);
}
