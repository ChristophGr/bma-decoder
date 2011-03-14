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

import java.io.File;
import java.security.InvalidKeyException;
import java.util.regex.Pattern;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;

public class App {
	private static final String HASH_XPATH = "/map/string[@name='com.blizzard.bma.AUTH_STORE.HASH']";
	private static final String MASK_KEY = "398e27fc50276a656065b0e525f4c06c04c61075286b8e7aeda59da9813b5dd6c80d2fb38068773fa59ba47c17ca6c6479015c1d5b8b8f6b9a";

	public static void main(String[] args) throws InvalidKeyException {
		if (args.length != 1) {
			System.err.println("Usage: decode <hash or xml-file>");
			return;
		}
		String arg = args[0];
		String tokenString;
		if (Pattern.matches("[a-f0-9]+", arg)) {
			tokenString = arg;
		} else {
			tokenString = getTokenStringFromFile(arg);
		}
		String unMask = unMask(tokenString);
		String secret = unMask.substring(0, 40);
		String serial = unMask.substring(40);
		System.out.println("Serial: " + serial);
		System.out.println("Secret: " + secret);
		Authenticator authenticator = new Authenticator(secret, true);
		System.out.println(authenticator.calculateKey());
	}

	private static String getTokenStringFromFile(String filename) {
		Document doc = parseInput(filename);
		XPathFactory xpathFactory = XPathFactory.newInstance();
		XPath xPath = xpathFactory.newXPath();
		XPathExpression xpathExpression;
		try {
			xpathExpression = xPath.compile(HASH_XPATH);
		} catch (XPathExpressionException e) {
			throw new RuntimeException(
					"predefined xpath-expression does not compile", e);
		}
		String result;
		try {
			result = (String) xpathExpression.evaluate(doc,
					XPathConstants.STRING);
		} catch (XPathExpressionException e) {
			throw new RuntimeException(String.format(
					"Error when applying XPath-Exression \"%s\" to document",
					HASH_XPATH));
		}
		return result;
	}

	private static Document parseInput(String filename) {
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(
					"could not even create a new transformer", e);
		}
		DOMResult result = new DOMResult();
		try {
			transformer.transform(new StreamSource(new File(filename)), result);
		} catch (TransformerException e) {
			throw new RuntimeException(String.format("Error parsing File %s",
					filename), e);
		}
		return (Document) result.getNode();
	}

	/* bit-operation-magic */
	private static String unMask(String masked) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < MASK_KEY.length(); i += 2) {
			String s = masked.substring(i, i + 2);
			int num = Integer.parseInt(s, 16);
			String s2 = MASK_KEY.substring(i, i + 2);
			int num2 = Integer.parseInt(s2, 16);
			int xord = num ^ num2;
			result.append(new Character((char) xord));
		}
		return result.toString();
	}
}
