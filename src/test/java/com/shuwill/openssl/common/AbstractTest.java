package com.shuwill.openssl.common;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

public abstract class AbstractTest {

    protected static final String CRYPTO_LIBRARY_NAME = "libcrypto";
    protected static final String NAITVE_LIBRARY_NAME = "libnatives";

    public static String getLibrary(String libraryName) throws IOException {
        final String osName = System.getProperty("os.name");
        final OsType os = OsType.resolve(osName);
        if (os == null || os == OsType.UNKNOWN) {
            throw new IllegalStateException("unknow operating system");
        }

        final String nativeLibType = os.nativeLibType().name();
        return Paths.get(
                new File("").getCanonicalPath(),
                "src/natives/libs",
                libraryName + "." + nativeLibType
        ).toString();
    }

}
