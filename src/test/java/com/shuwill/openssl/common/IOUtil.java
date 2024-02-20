package com.shuwill.openssl.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Random;
import java.util.UUID;

public class IOUtil {

    public static final int BUFFER_SIZE = 8192;

    public static Path createRandomFile(int size, SizeUnit sizeUnit) throws IOException {
        final String classPath = ClassUtil.getClassPath();
        Path path = Paths.get(classPath, UUID.randomUUID().toString());
        long writed = 0;
        final Random random = new Random();
        long fileSize = sizeUnit.toByte(size);
        if (fileSize <= BUFFER_SIZE) {
            byte[] buffer = new byte[(int) fileSize];
            random.nextBytes(buffer);
            Files.write(path, buffer, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } else {
            while (writed < fileSize) {
                byte[] buffer = new byte[BUFFER_SIZE];
                random.nextBytes(buffer);
                Files.write(path, buffer, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                writed = writed + BUFFER_SIZE;
            }
        }
        return path;
    }
}
