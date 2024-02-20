/*
 *    Copyright [2019] [shuwei.wang (c) wswill@foxmail.com]
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.shuwill.openssl.common;

import java.io.File;
import java.io.InputStream;
import java.util.Objects;

/**
 * ClassUtil
 *
 * @author shuwei.wang
 * @since 1.0.0
 */
public abstract class ClassUtil {

    private static final String MAIN_METHOD_NAME = "main";

    /**
     * get the thread context class loader
     *
     * @return ClassLoader
     */
    public static ClassLoader getContextClassLoader() {
        return Thread.currentThread().getContextClassLoader();
    }

    public static ClassLoader getClassLoader() {
        ClassLoader classLoader = getContextClassLoader();
        if (classLoader == null) {
            classLoader = ClassUtil.class.getClassLoader();
            if (classLoader == null) {
                classLoader = ClassLoader.getSystemClassLoader();
            }
        }
        return classLoader;
    }

    public static String getClassPath() {
        return new File(Objects.requireNonNull(getClassLoader().getResource("")).getPath()).getPath();
    }

    public static InputStream getResourceAsStream(String resource) {
        return getClassLoader().getResourceAsStream(resource);
    }

    /**
     * 获取含有main方法的类
     *
     * @return main方法的类
     */
    public static Class<?> deduceMainClass() {
        try {
            StackTraceElement[] stackTrace = new RuntimeException().getStackTrace();
            for (StackTraceElement traceElement : stackTrace) {
                if (MAIN_METHOD_NAME.equals(traceElement.getMethodName())) {
                    return Class.forName(traceElement.getClassName());
                }
            }
        } catch (ClassNotFoundException ignored) {

        }
        return null;
    }
}
