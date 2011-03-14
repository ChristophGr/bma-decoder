/*
The MIT License

Copyright (c) 2010 Christoph Gritschenberger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

package com.github.bmadecoder;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.EndianUtils;
import org.apache.commons.lang.ArrayUtils;

public class Authenticator {

	private Mac mac;
	private boolean syncing;

	public Authenticator(String secret) throws InvalidKeyException {
		this(secret, false);
	}

	public Authenticator(byte[] secret) throws InvalidKeyException {
		this(secret, false);
	}

	public Authenticator(String secret, boolean syncing)
			throws InvalidKeyException {
		this.syncing = syncing;
		byte[] internalToken = parseToken(secret);
		init(internalToken);
	}

	public Authenticator(byte[] secret, boolean syncing)
			throws InvalidKeyException {
		this.syncing = syncing;
		init(secret);
	}

	public static byte[] parseToken(String token) {
		byte btoken[] = new byte[20];
		for (int i = 0; i < token.length() / 2; i++) {
			String byteString = token.substring(i * 2, i * 2 + 2);
			btoken[i] = (byte) Integer.parseInt(byteString, 16);
		}
		return btoken;
	}

	private void init(byte[] internalToken) throws InvalidKeyException {
		SecretKeySpec secretKeySpec = new SecretKeySpec(internalToken,
				"HmacSHA1");
		try {
			mac = Mac.getInstance("HmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		mac.init(secretKeySpec);
	}

	public int calculateKey() {
		return calculateKey(getTimeslot());
	}

	public int calculateKey(long timeslot) {
		byte[] time2 = getLongAsByteArray(timeslot);
		byte[] result = mac.doFinal(time2);
		int code = selectInt(result) % 100000000;
		return code;
	}

	/*
	 * calculate current interval number long
	 *
	 * intervalNumber = (CLIENT_TIME_IN_MILLISECONDS +
	 * TIME_DIFFERENCE_TO_SERVER) / 30000
	 */
	public long getTimeslot() {
		long timeDiff = getTimeDiff();
		System.err.println("timediff was " + timeDiff);
		long intervalNum = (System.currentTimeMillis() + timeDiff) / 30000L;
		return intervalNum;
	}

	private static int selectInt(byte input[]) {
		int i = selectPos(input);
		byte[] subarray = ArrayUtils.subarray(input, i, i + 4);
		subarray[0] = (byte) (subarray[0] & 0x7f);
		int readSwappedInteger = EndianUtils.readSwappedInteger(subarray, 0);
		int result = EndianUtils.swapInteger(readSwappedInteger);
		return result;
	}

	private static int selectPos(byte[] input) {
		return input[input.length - 1] & 0xf;
	}

	private static byte[] getLongAsByteArray(long intervalNum) {
		byte[] time2 = new byte[8];
		long swapped = EndianUtils.swapLong(intervalNum);
		EndianUtils.writeSwappedLong(time2, 0, swapped);
		return time2;
	}

	public long getTimeDiff() {
		if (!this.syncing) {
			return 0;
		}
		try {
			URL url = URI
					.create("http://m.eu.mobileservice.blizzard.com/enrollment/time.htm")
					.toURL();
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setRequestProperty("Content-type", "application/octet-stream");
			conn.setRequestProperty("Accept",
					"text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2");
			conn.setReadTimeout(10000);
			conn.setDoInput(true);
			conn.connect();

			byte[] servertime = new byte[8];
			InputStream connectionStream = conn.getInputStream();
			connectionStream.read(servertime, 0, 8);
			connectionStream.close();
			conn.disconnect();

			return new BigInteger(servertime).longValue()
					- System.currentTimeMillis();
		} catch (MalformedURLException e) {
			throw new IllegalStateException(e);
		} catch (IOException e) {
			return 0;
		}
	}
}
