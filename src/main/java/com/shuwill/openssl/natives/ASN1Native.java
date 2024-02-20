package com.shuwill.openssl.natives;

import com.shuwill.openssl.natives.pointer.ASN1_INTEGER;
import com.shuwill.openssl.natives.pointer.ASN1_OBJECT;
import com.shuwill.openssl.natives.pointer.ASN1_OCTET_STRING;
import com.shuwill.openssl.natives.pointer.ASN1_TIME;
import com.shuwill.openssl.natives.pointer.X509;

public interface ASN1Native extends CommonNative {

    int MBSTRING_FLAG = 0x1000;
    int MBSTRING_UTF8 = (MBSTRING_FLAG);
    int MBSTRING_ASC = (MBSTRING_FLAG | 1);
    int MBSTRING_BMP = (MBSTRING_FLAG | 2);
    int MBSTRING_UNIV = (MBSTRING_FLAG | 4);

    /**
     * OBJ_nid2obj(), OBJ_nid2ln() and OBJ_nid2sn() convert the NID n to an ASN1_OBJECT structure,
     * its long name and its short name respectively, or NULL if an error occurred.
     *
     * @param n
     * @return
     */
    ASN1_OBJECT OBJ_nid2obj(int n);

    String OBJ_nid2ln(int n);

    String OBJ_nid2sn(int n);

    /**
     * OBJ_obj2nid(), OBJ_ln2nid(), OBJ_sn2nid() return the corresponding NID for the object o,
     * the long name ln or the short name sn respectively or NID_undef if an error occurred.
     *
     * @param o
     * @return
     */
    int OBJ_obj2nid(ASN1_OBJECT o);

    int OBJ_ln2nid(String s);

    int OBJ_sn2nid(String s);

    /**
     * returns NID corresponding to text string s. s can be a long name, a short name or the numerical representation of an object.
     *
     * @param s
     * @return
     */
    int OBJ_txt2nid(String s);

    /**
     * converts the text string s into an ASN1_OBJECT structure.
     * If no_name is 0 then long names and short names will be interpreted as well as numerical forms. I
     * If no_name is 1 only the numerical form is acceptable.
     *
     * @param s
     * @param no_name
     * @return
     */
    ASN1_OBJECT OBJ_txt2obj(String s, int no_name);

    /**
     * converts the ASN1_OBJECT into a textual representation.
     * Unless buf is NULL, the representation is written as a NUL-terminated string to buf, where at most buf_len bytes are written, truncating the result if necessary.
     * In any case it returns the total string length, excluding the NUL character, required for non-truncated representation, or -1 on error.
     * If no_name is 0 then if the object has a long or short name then that will be used, otherwise the numerical form will be used.
     * If no_name is 1 then the numerical form will always be used.
     *
     * @param buf
     * @param buf_len
     * @param a
     * @param no_name
     * @return
     */
    int OBJ_obj2txt(byte[] buf, int buf_len, ASN1_OBJECT a, int no_name);

    /**
     * compares a to b. If the two are identical 0 is returned.
     *
     * @param a
     * @param b
     * @return
     */
    int OBJ_cmp(ASN1_OBJECT a, ASN1_OBJECT b);

    /**
     * allocates and initializes an ASN1_OBJECT structure.
     *
     * @return
     */
    ASN1_OBJECT ASN1_OBJECT_new();

    /**
     * frees up the ASN1_OBJECT structure. If is NULL, nothing is done.
     *
     * @param a
     */
    void ASN1_OBJECT_free(ASN1_OBJECT a);

    ASN1_TIME ASN1_TIME_new();

    void ASN1_TIME_free(ASN1_TIME time);

    int ASN1_TIME_set_string(ASN1_TIME s, String str);

    ASN1_TIME X509_gmtime_adj(long adj);

    ASN1_INTEGER ASN1_INTEGER_new();

    int ASN1_INTEGER_set(ASN1_INTEGER a, long v);

    void ASN1_INTEGER_free(ASN1_INTEGER a);

    ASN1_OCTET_STRING ASN1_OCTET_STRING_new();

    int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING str, byte[] data, int len);

    void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING str);

    ASN1_INTEGER X509_get_serialNumber(X509 x);

    ASN1_TIME X509_get_notBefore(X509 x);

    ASN1_TIME X509_get_notAfter(X509 x);
}
