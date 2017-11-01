/*
 * Copyright 2007 Soren Davidsen, Tanesha Networks
 *  
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tanesha.recaptcha;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Properties;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import net.tanesha.recaptcha.http.HttpLoader;
import net.tanesha.recaptcha.http.SimpleHttpLoader;

public class ReCaptchaImpl implements ReCaptcha {

	public static final String PROPERTY_THEME = "theme";
	public static final String PROPERTY_TABINDEX = "tabindex";

	private static final String HTTP_SERVER_V1 = "http://www.google.com/recaptcha/api";
	private static final String HTTPS_SERVER_V1 = "https://www.google.com/recaptcha/api";
	private static final String HTTP_SERVER_V2 = "http://www.google.com/recaptcha/api.js";
	private static final String HTTPS_SERVER_V2 = "https://www.google.com/recaptcha/api.js";
	private static final String HTTPS_VERIFY_URL_V1 = "http://www.google.com/recaptcha/api/verify";
	private static final String HTTPS_VERIFY_URL_V2 = "https://www.google.com/recaptcha/api/siteverify";

	private String privateKey;
	private String publicKey;
	private boolean https = true;
	private boolean includeNoscript = false;
	private HttpLoader httpLoader = new SimpleHttpLoader();
	private Version version;

	public boolean isHttps() {
		return https;
	}

	public Version getVersion() {
		return version;
	}

	public void setVersion(Version version) {
		this.version = version;
	}

	public void setHttps(boolean https) {
		this.https = https;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public void setIncludeNoscript(boolean includeNoscript) {
		this.includeNoscript = includeNoscript;
	}

	public void setHttpLoader(HttpLoader httpLoader) {
		this.httpLoader = httpLoader;
	}

	@SuppressWarnings("unchecked")
	public ReCaptchaResponse checkAnswer(String remoteAddr, String challenge, String response) {

		String message = null;

		try {
			String errorMessage = null;
			boolean valid = false;

			switch (version) {
			case V2:
				message = httpLoader.httpPost(https ? HTTPS_VERIFY_URL_V2 : HTTPS_VERIFY_URL_V2,
						"secret=" + URLEncoder.encode(privateKey, "UTF-8") + "&remoteip="
								+ URLEncoder.encode(remoteAddr, "UTF-8") + "&response="
								+ URLEncoder.encode(response, "UTF-8"));
				if (message != null) {
					JSONObject obj = (JSONObject) JSONValue.parse(message);
					valid = Boolean.TRUE.equals((Boolean) obj.get("success"));
					
					JSONArray arr = (JSONArray) obj.get("error-codes");
					if (arr != null) {
						StringBuilder b = new StringBuilder();
						for (Object o : arr) {
							if (b.length() > 0)
								b.append(" ");
							b.append(o.toString());
						}
						errorMessage = b.toString();
					}

					return new ReCaptchaResponse(valid, errorMessage);
				}
				break;
			default:
				message = httpLoader.httpPost(https ? HTTPS_VERIFY_URL_V2 : HTTPS_VERIFY_URL_V1,
						"privatekey=" + URLEncoder.encode(privateKey, "UTF-8") + "&remoteip="
								+ URLEncoder.encode(remoteAddr, "UTF-8") + "&challenge="
								+ URLEncoder.encode(challenge, "UTF-8") + "&response="
								+ URLEncoder.encode(response, "UTF-8"));

				if (message != null) {

					String[] a = message.split("\r?\n");
					if (a.length < 1) {
						return new ReCaptchaResponse(false, "No answer returned from recaptcha: " + message);
					}
					valid = "true".equals(a[0]);
					if (!valid) {
						if (a.length > 1)
							errorMessage = a[1];
						else
							errorMessage = "recaptcha4j-missing-error-message";
					}

					return new ReCaptchaResponse(valid, errorMessage);
				}
			}

			return new ReCaptchaResponse(false, "recaptcha-not-reachable");
		} catch (ReCaptchaException networkProblem) {
			return new ReCaptchaResponse(false, "recaptcha-not-reachable");
		} catch (UnsupportedEncodingException uee) {
			throw new UnsupportedOperationException("UTF-8 encoding not supported.");
		}
	}

	public String createHeadHtml(Properties options) {
		switch (version) {
		case V2:
			String server = https ? HTTPS_SERVER_V2 : HTTP_SERVER_V2;
			return "<script type=\"text/javascript\" src=\"" + server + "\"></script>\r\n";
		default:
			return null;
		}
	}

	public String createRecaptchaHtml(String errorMessage, Properties options) {

		try {
			String errorPart = (errorMessage == null ? "" : "&amp;error=" + URLEncoder.encode(errorMessage, "UTF-8"));
			String message;

			switch (version) {
			case V2:
				String server = https ? HTTPS_SERVER_V2 : HTTP_SERVER_V2;
				message = "<div class=\"g-recaptcha\" " + fetchDataOptions(options) + "  data-sitekey=\"" + publicKey
						+ "\"></div>\r\n";
				break;
			default:
				server = https ? HTTPS_SERVER_V1 : HTTP_SERVER_V1;
				message = fetchJSOptions(options) + "<script type=\"text/javascript\" src=\"" + server + "/challenge?k="
						+ publicKey + errorPart + "\"></script>\r\n";
				if (includeNoscript) {
					message += "<noscript>\r\n" + "	<iframe src=\"" + server + "/noscript?k=" + publicKey + errorPart
							+ "\" height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br/>\r\n"
							+ "	<textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\"></textarea>\r\n"
							+ "	<input type=\"hidden\" name=\"recaptcha_response_field\" value=\"manual_challenge\"/>\r\n"
							+ "</noscript>";
				}
				break;
			}

			return message;
		} catch (UnsupportedEncodingException uee) {
			throw new UnsupportedOperationException("UTF-8 encoding not supported.");
		}
	}

	public String createRecaptchaHtml(String errorMessage, String theme, Integer tabindex) {

		Properties options = new Properties();

		if (theme != null) {
			options.setProperty(PROPERTY_THEME, theme);
		}
		if (tabindex != null) {
			options.setProperty(PROPERTY_TABINDEX, String.valueOf(tabindex));
		}

		return createRecaptchaHtml(errorMessage, options);
	}

	/**
	 * Produces javascript array with the RecaptchaOptions encoded.
	 * 
	 * @param properties
	 * @return
	 */
	private String fetchJSOptions(Properties properties) {

		if (properties == null || properties.size() == 0) {
			return "";
		}

		String jsOptions = "<script type=\"text/javascript\">\r\n" + "var RecaptchaOptions = {";

		for (Enumeration<?> e = properties.keys(); e.hasMoreElements();) {
			String property = (String) e.nextElement();

			jsOptions += property + ":'" + properties.getProperty(property) + "'";

			if (e.hasMoreElements()) {
				jsOptions += ",";
			}

		}

		jsOptions += "};\r\n</script>\r\n";

		return jsOptions;
	}

	/**
	 * Produces HTML attributes string with the options encoded.
	 * 
	 * @param properties
	 * @return
	 */
	private String fetchDataOptions(Properties properties) {

		if (properties == null || properties.size() == 0) {
			return "";
		}

		String dataOptions = "";
		for (Enumeration<?> e = properties.keys(); e.hasMoreElements();) {
			String property = (String) e.nextElement();
			dataOptions += "data-" + property + "=\"" + properties.getProperty(property) + "\" ";

		}
		return dataOptions;
	}
}
