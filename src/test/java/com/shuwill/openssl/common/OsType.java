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

import java.util.HashMap;
import java.util.Map;


/**
 * arch type
 * @author shuwei.wang
 * @since 1.0.0
 */
public enum OsType {

	WINDOWS("windows"),
	LINUX("linux"),
	MACOS("macos"),
	AIX("AIX"),
	HPUX("HP-UX"),
	OS400("OS/400"),
	IRIX("Irix"),
	FreeBSD("FreeBSD"),
	OpenBSD("OpenBSD"),
	NetBSD("NetBSD"),
	OS2("OS/2"),
	SOLARIS("Solaris"),
	SUNOS("SunOS"),
	UNKNOWN("UNKNOW");

	private static final Map<String, OsType> types = new HashMap<>(16);

	static {
		for (OsType type : OsType.values()) {
			types.put(type.name, type);
		}
	}

	private final String name;

	OsType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public NativeLibType nativeLibType() {
		switch (this){
			case WINDOWS:
				return NativeLibType.dll;
            case MACOS:
				return NativeLibType.dylib;
			default:
				return NativeLibType.so;
		}
	}

	public static OsType resolve(String osname) {
		for (Map.Entry<String, OsType> entry : types.entrySet()) {
			if (trimAll(osname).toUpperCase().contains(entry.getKey().toUpperCase())) {
				return entry.getValue();
			}
		}
		return UNKNOWN;
	}


	private static String trimAll(final String source) {
		int len = source.length();
		StringBuilder sb = new StringBuilder(len);
		for (int i = 0; i < len; i++) {
			char c = source.charAt(i);
			if (!Character.isWhitespace(c)) {
				sb.append(c);
			}
		}
		return sb.toString();
	}
}
