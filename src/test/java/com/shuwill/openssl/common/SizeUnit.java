/*
 * Copyright [4/8/20 2:34 PM] [shuwei.wang (c) wswill@foxmail.com]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.shuwill.openssl.common;

/**
 * size unit
 * @author shuwei.wang
 * @since 1.0.0
 */
public enum SizeUnit {

	B{
		public long toByte(long d) {return d;}
		public long toKilobyte(long d) {return d / UNIT_SIZE;}
		public long toMegabyte(long d) {return d / Double.valueOf(Math.pow(UNIT_SIZE, 2)).longValue();}
		public long toGigabyte(long d) {return d / Double.valueOf(Math.pow(UNIT_SIZE, 3)).longValue();}
		public long toTrillionbyte(long d) {return d / Double.valueOf(Math.pow(UNIT_SIZE, 4)).longValue();}
	},

	KB{
		public long toByte(long d) {return d * UNIT_SIZE;}
		public long toKilobyte(long d) {return d;}
		public long toMegabyte(long d) {return d / UNIT_SIZE;}
		public long toGigabyte(long d) {return d / Double.valueOf(Math.pow(UNIT_SIZE, 2)).longValue();}
		public long toTrillionbyte(long d) {return d / Double.valueOf(Math.pow(UNIT_SIZE, 3)).longValue();}
	},

	MB{
		public long toByte(long d) {return d * Double.valueOf(Math.pow(UNIT_SIZE, 2)).longValue();}
		public long toKilobyte(long d) {return d * UNIT_SIZE;}
		public long toMegabyte(long d) {return d;}
		public long toGigabyte(long d) {return d / Double.valueOf(Math.pow(UNIT_SIZE, 1)).longValue();}
		public long toTrillionbyte(long d) {return d / Double.valueOf(Math.pow(UNIT_SIZE, 2)).longValue();}
	},

	GB{
		public long toByte(long d) {return d * Double.valueOf(Math.pow(UNIT_SIZE, 3)).longValue();}
		public long toKilobyte(long d) {return d * Double.valueOf(Math.pow(UNIT_SIZE, 2)).longValue();}
		public long toMegabyte(long d) {return d * UNIT_SIZE;}
		public long toGigabyte(long d) {return d;}
		public long toTrillionbyte(long d) {return d / UNIT_SIZE;}
	},

	TB{
		public long toByte(long d) {return d * Double.valueOf(Math.pow(UNIT_SIZE, 4)).longValue();}
		public long toKilobyte(long d) {return d * Double.valueOf(Math.pow(UNIT_SIZE, 3)).longValue();}
		public long toMegabyte(long d) {return d * Double.valueOf(Math.pow(UNIT_SIZE, 2)).longValue();}
		public long toGigabyte(long d) {return d * UNIT_SIZE;}
		public long toTrillionbyte(long d) {return d;}
	};

	private static final int UNIT_SIZE = 1024;

	public abstract long toByte(long d);
}
