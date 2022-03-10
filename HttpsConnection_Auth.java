package com.fss.pgservlet;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


public class HttpsConnection_Auth {

	public String testMasterCard() {
		String str = null;
		byte abyte0[] = null;
		String url = null;
		try {
//			url = "https://pit-wsi.3dsecure.net:5443/ds";
			url = "https://mcdirectory.securecode.com/";
//			url = "https://directory.securecode.com";
			String messageId = new Date().getTime() + "";

//			String VEREQ = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ThreeDSecure><Message id=\""+ messageId+"\"><VEReq><version>1.0.2</version><pan>5172526727704616</pan><Merchant><acqBIN>521538</acqBIN><merID>3124130444560</merID></Merchant><Browser></Browser></VEReq></Message></ThreeDSecure>";
			String VEREQ = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ThreeDSecure><Message id=\""+ messageId+"\"><VEReq><version>1.0.2</version><pan>5172526727704616</pan><Merchant><acqBIN>521538</acqBIN><merID>3124130444560</merID></Merchant><Browser><accept>text/html,application/xhtml+xml,application/xml;q=0.9,/*;q=0.8</accept><userAgent>Mozilla/5.0 &amp; #40;iPhone; CPU iPhone OS 14_4_2 like Mac OS X&amp; #41; AppleWebKit/605.1.15 &amp; #40;KHTML, like Gecko&amp; #41; Version/14.0.3 Mobile/15E148 Safari/604.1</userAgent></Browser></VEReq></Message></ThreeDSecure>";

			
			System.out.println("VEREQ..." + VEREQ);
			abyte0 = sendMessage(url, VEREQ.getBytes(), "POST", "application/xml; charset=utf-8", false);
			str = new String(abyte0);
			System.out.println("VERES..." + str);
		} catch (Exception e) {
			for (int i = 0; i < e.getStackTrace().length; i++) {
				str = str + e.getStackTrace()[i] + "<br>";
			}
		}
		str = "Connecting... " + url + "<br>" + str;
		return str;
	}

	public String testOmanNetCard() {
		String str = null;
		byte abyte0[] = null;
		String url = null;
		try {
			url = "https://certepayments.omannet.om/PG/VPAS.htm?actionVPAS=processIVROTPReq";

			String VEREQ = "<request><paymentid>302202127576115127</paymentid><trackid>1633147633058</trackid><otp>3782</otp><udf1>OTP</udf1><udf2>udf 222 value</udf2><udf3>udf 333 value</udf3><udf4>udf 444 value</udf4><id>ipay707336589914</id><password>Shopping@123</password><udf5>c73a2154b3992f3235cbc75ab3306dd7569d151dfd704853399186df6a3d242c</udf5></request>";

			
			System.out.println("VEREQ..." + VEREQ);
			abyte0 = connect(url, VEREQ.getBytes(), "POST", "application/xml; charset=utf-8", false);
			str = new String(abyte0);
			System.out.println("VERES..." + str);
		} catch (Exception e) {
			for (int i = 0; i < e.getStackTrace().length; i++) {
				str = str + e.getStackTrace()[i] + "<br>";
			}
		}
		str = "Connecting... " + url + "<br>" + str;
		return str;
	}

	public String testSecurePayment() {
		String str = null;
		byte abyte0[] = null;
		String url = null;
		try {
			url = "https://securepayments.oabipay.com/trxns/VPAS.htm?actionVPAS=tranInit";

			String VEREQ = "<request><card>4862698908509409</card><cvv2>123</cvv2><currencycode>512</currencycode><expyear>2021</expyear><expmonth>12</expmonth><member>Cardholders Name</member><amt>1.100</amt><action>1</action><trackid>1633141678820</trackid><udf1>udf 111 value</udf1><udf2>udf 222 value</udf2><udf3>udf 333 value</udf3><udf4>udf 444 value</udf4><udf5>udf 555 value</udf5><currencycode>512</currencycode><id>ipay830205955338</id><password>OABTEST@2018</password><errorURL>http://localhost:8080/merchantPlugin/shopping/merchanthostedvbvtcp/vbvTranPipeError.jsp</errorURL><responseURL>http://localhost:8080/merchantPlugin/shopping/merchanthostedvbvtcp/vbvTranPipeResult.jsp</responseURL></request>";

			
			System.out.println("VEREQ..." + VEREQ);
			abyte0 = connect(url, VEREQ.getBytes(), "POST", "application/xml; charset=utf-8", false);
			str = new String(abyte0);
			System.out.println("VERES..." + str);
		} catch (Exception e) {
			for (int i = 0; i < e.getStackTrace().length; i++) {
				str = str + e.getStackTrace()[i] + "<br>";
			}
		}
		str = "Connecting... " + url + "<br>" + str;
		return str;
	}
	
	public String testA2ACard() {
		String str = null;
		byte abyte0[] = null;
		String url = null;
		try {
			url = "https://api-ewallet.lamma.om/Global.eWalletAPI/api/base/A2AProcess";

			String VEREQ = "{\r\n" + 
					"    \"A2ARequest\": {\r\n" + 
					"        \"Header\": {\r\n" + 
					"            \"SrvID\": \"PendingRegisterCust\",\r\n" + 
					"                       \"Channel\": \"MO\",\r\n" + 
					"            \"DeviceID\": \"564\",\r\n" + 
					"            \"UserID\": \"A2A\",\r\n" + 
					"            \"Password\": \"mIPKye4+rhU=\",\r\n" + 
					"            \"Token\": \"OgasjtiaAPB5Rv7jtyWo6u92etEsJDp87R8pFwRaabTJGTs4ecD2+sAU6cWhWNQPsLFKihcm3w9q3PjXt7gtGq2Crfa7rRP1fYMpKVA27U4=\"\r\n" + 
					"        },\r\n" + 
					"        \"Body\": {\r\n" + 
					"            \"StepNumber\": \"1\",\r\n" + 
					"            \"CustProfile\": {\r\n" + 
					"                \"DateBirth\": \"03/04/1991\",\r\n" + 
					"                \"NationalityID\": \"991509626276\",\r\n" + 
					"                \"MobileNumber\": \"970597628221\",\r\n" + 
					"                \"NationalityCode\": \"400\",\r\n" + 
					"                \"FirstName\": \"Ahmad\",\r\n" + 
					"                \"MidName\": \"Mustafa\",\r\n" + 
					"                \"LastName\": \"Alkhateeb\",\r\n" + 
					"                \"ThirdName\": \"Mohammed\",\r\n" + 
					"                \"Alias\": \"\",\r\n" + 
					"                \"FaceImage\":\"\",\r\n" + 
					"                \"BackImage\": \"\",\r\n" + 
					"                \"DocImage\": \"\",\r\n" + 
					"                \"CustIDType\": \"777\",\r\n" + 
					"                \"Password\": \"Mr@1639\",\r\n" + 
					"                \"PIN\": \"2226\",\r\n" + 
					"                \"Gender\": \"M\",\r\n" + 
					"                \"Governorate\": \"1\",\r\n" + 
					"                \"Email\": \"\",\r\n" + 
					"                \"StreetName\": \"\",\r\n" + 
					"                \"BuildingNo\": \"\"\r\n" + 
					"               \r\n" + 
					"            }\r\n" + 
					"        },\r\n" + 
					"        \"Footer\": {\r\n" + 
					"            \"Signature\": \"\"\r\n" + 
					"        }\r\n" + 
					"    }\r\n" + 
					"}";

			
			System.out.println("VEREQ..." + VEREQ);
			abyte0 = sendA2AMessage(url, VEREQ.getBytes(), "POST", "application/json; charset=utf-8", false);
			str = new String(abyte0);
			System.out.println("VERES..." + str);
		} catch (Exception e) {
			for (int i = 0; i < e.getStackTrace().length; i++) {
				str = str + e.getStackTrace()[i] + "<br>";
			}
		}
		str = "Connecting... " + url + "<br>" + str;
		return str;
	}


	
	public byte[] sendMessage(String hostURL, byte msg[], String requestMethod, String contentType,
			boolean noResponse) {
		URL url = null;
		BufferedOutputStream out = null;
		BufferedInputStream in = null;
		HttpURLConnection sendURL = null;
		try {
			try {
				url = new URL(hostURL.trim());
			} catch (MalformedURLException e) {
			}
			if (url == null) {
				return null;
			}
			KeyManager[] km = null;
			TrustManager[] tm = null;
			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			System.setProperty("javax.net.debug", "all");
			System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");
			FileInputStream keyStream = null;
			String keystorepass = "password";
			try {
				// keyStream = new FileInputStream(new
				// File("D:\\Sundaresh\\webserverproject\\config\\sslkeystore.bin"));
				keyStream = new FileInputStream(new File("S:\\OAB Projects\\development\\supportingfile\\Keys\\3dsecure\\MasterCardCert\\newwork_210720201\\key\\securepayments.oabipay.com\\keystore.jks"));
//				keyStream = new FileInputStream(new File("/opt/ijtimaati/sslkeystore-MC.bin"));
				KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] keyPassword = keystorepass.trim().toCharArray();
				keyStore.load(keyStream, keyPassword);
				KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				keyFactory.init(keyStore, keyPassword);
				km = keyFactory.getKeyManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (keyStream != null) {
					keyStream.close();
					keyStream = null;
				}
			}
			FileInputStream trustStream = null;
			try {
				// trustStream = new FileInputStream(new
				// File("D:\\Sundaresh\\webserverproject\\config\\truststore.bin"));
				trustStream = new FileInputStream(new File("S:\\OAB Projects\\development\\webservercert\\MC\\truststore-MC.bin"));
//				trustStream = new FileInputStream(new File("/opt/ijtimaati/truststore-MC.bin"));
				KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] trustPassword = keystorepass.trim().toCharArray();
				trustStore.load(trustStream, trustPassword);
				TrustManagerFactory trustFactory = TrustManagerFactory
						.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				trustFactory.init(trustStore);
				tm = trustFactory.getTrustManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (trustStream != null) {
					trustStream.close();
					trustStream = null;
				}
			}
			sslContext.init(km, tm, null);
			javax.net.ssl.SSLSocketFactory sslFactory = sslContext.getSocketFactory();
			HttpsURLConnection.setDefaultSSLSocketFactory(sslFactory);
			sendURL = (HttpURLConnection) url.openConnection();
			requestMethod = requestMethod.toUpperCase();
			if (!requestMethod.equals("POST") && !requestMethod.equals("GET")) {
				return null;
			}
			sendURL.setRequestMethod(requestMethod);
			sendURL.setDoOutput(true);
			sendURL.setDoInput(true);
			sendURL.setAllowUserInteraction(false);
			if (contentType != null)
				sendURL.setRequestProperty("Content-Type", contentType);
			if (msg != null && msg.length > 0) {
				sendURL.setRequestProperty("Content-Length", String.valueOf(msg.length));
				out = new BufferedOutputStream(sendURL.getOutputStream());
				out.write(msg, 0, msg.length);
				out.flush();
				out.close();
			}
			if (noResponse)
				return null;
			int length = sendURL.getContentLength();
			byte bytes[];
			if (length < 0) {
				ByteArrayOutputStream bout = new ByteArrayOutputStream(128);
				in = new BufferedInputStream(sendURL.getInputStream());
				do {
					int b = in.read();
					if (b == -1)
						break;
					bout.write(b);
				} while (true);
				bytes = bout.toByteArray();
				return bytes;
			}
			bytes = new byte[length];
			in = new BufferedInputStream(sendURL.getInputStream());
			int pos;
			int numBytesRead;
			for (pos = 0; pos < length; pos += numBytesRead) {
				numBytesRead = in.read(bytes, pos, length - pos);
				if (numBytesRead != -1)
					continue;
				break;
			}
			return bytes;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (out != null) {
					try {
						out.close();
					} catch (Exception ex) {
					}
					out = null;
				}
				if (in != null) {
					try {
						in.close();
					} catch (Exception ex) {
					}
					in = null;
				}
			} catch (Exception e) {
			}
		}
		return null;
	}

	public byte[] send3DsMessage(String hostURL, byte msg[], String requestMethod, String contentType,
			boolean noResponse) {
		URL url = null;
		BufferedOutputStream out = null;
		BufferedInputStream in = null;
		HttpURLConnection sendURL = null;
		try {
			try {
				url = new URL(hostURL.trim());
			} catch (MalformedURLException e) {
			}
			if (url == null) {
				return null;
			}
			KeyManager[] km = null;
			TrustManager[] tm = null;
			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			System.setProperty("javax.net.debug", "all");
			System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");

			FileInputStream keyStream = null;
//			String keystorepass = "password";
			String keystorepass = "V1s@3ds2";
			
			try {
				// keyStream = new FileInputStream(new
				// File("D:\\Sundaresh\\webserverproject\\config\\sslkeystore.bin"));
				keyStream = new FileInputStream(new File("S:\\OAB_Projects\\development\\webservercert\\VISA3ds2\\certpayments.jks"));
//				keyStream = new FileInputStream(new File("/opt/ijtimaati/sslkeystore-MC.bin"));
				KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] keyPassword = keystorepass.trim().toCharArray();
				keyStore.load(keyStream, keyPassword);
				KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				keyFactory.init(keyStore, keyPassword);
				km = keyFactory.getKeyManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (keyStream != null) {
					keyStream.close();
					keyStream = null;
				}
			}
			FileInputStream trustStream = null;
			try {
				// trustStream = new FileInputStream(new
				// File("D:\\Sundaresh\\webserverproject\\config\\truststore.bin"));
				trustStream = new FileInputStream(new File("S:\\OAB_Projects\\development\\webservercert\\VISA3ds2\\certpayments.jks"));
//				trustStream = new FileInputStream(new File("/opt/ijtimaati/truststore-MC.bin"));
				KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] trustPassword = keystorepass.trim().toCharArray();
				trustStore.load(trustStream, trustPassword);
				TrustManagerFactory trustFactory = TrustManagerFactory
						.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				trustFactory.init(trustStore);
				tm = trustFactory.getTrustManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (trustStream != null) {
					trustStream.close();
					trustStream = null;
				}
			}
			sslContext.init(km, tm, null);
			javax.net.ssl.SSLSocketFactory sslFactory = sslContext.getSocketFactory();
			HttpsURLConnection.setDefaultSSLSocketFactory(sslFactory);
			sendURL = (HttpURLConnection) url.openConnection();
			requestMethod = requestMethod.toUpperCase();
			if (!requestMethod.equals("POST") && !requestMethod.equals("GET")) {
				return null;
			}
			sendURL.setRequestMethod(requestMethod);
			sendURL.setDoOutput(true);
			sendURL.setDoInput(true);
			sendURL.setAllowUserInteraction(false);
			if (contentType != null)
				sendURL.setRequestProperty("Content-Type", contentType);
			if (msg != null && msg.length > 0) {
				sendURL.setRequestProperty("Content-Length", String.valueOf(msg.length));
				out = new BufferedOutputStream(sendURL.getOutputStream());
				out.write(msg, 0, msg.length);
				out.flush();
				out.close();
			}
			if (noResponse)
				return null;
			int length = sendURL.getContentLength();
			byte bytes[];
			if (length < 0) {
				ByteArrayOutputStream bout = new ByteArrayOutputStream(128);
				in = new BufferedInputStream(sendURL.getInputStream());
				do {
					int b = in.read();
					if (b == -1)
						break;
					bout.write(b);
				} while (true);
				bytes = bout.toByteArray();
				return bytes;
			}
			bytes = new byte[length];
			in = new BufferedInputStream(sendURL.getInputStream());
			int pos;
			int numBytesRead;
			for (pos = 0; pos < length; pos += numBytesRead) {
				numBytesRead = in.read(bytes, pos, length - pos);
				if (numBytesRead != -1)
					continue;
				break;
			}
			return bytes;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (out != null) {
					try {
						out.close();
					} catch (Exception ex) {
					}
					out = null;
				}
				if (in != null) {
					try {
						in.close();
					} catch (Exception ex) {
					}
					in = null;
				}
			} catch (Exception e) {
			}
		}
		return null;
	}


	
	public byte[] sendA2AMessage(String hostURL, byte msg[], String requestMethod, String contentType,
			boolean noResponse) {
		URL url = null;
		BufferedOutputStream out = null;
		BufferedInputStream in = null;
		HttpURLConnection sendURL = null;
		try {
			try {
				url = new URL(hostURL.trim());
			} catch (MalformedURLException e) {
			}
			if (url == null) {
				return null;
			}
			KeyManager[] km = null;
			TrustManager[] tm = null;
			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			System.setProperty("javax.net.debug", "all");
			System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");
			FileInputStream keyStream = null;
			String keystorepass = "password";
			try {
				disableSSLVerification();
				// keyStream = new FileInputStream(new
				// File("D:\\Sundaresh\\webserverproject\\config\\sslkeystore.bin"));
				keyStream = new FileInputStream(new File("S:\\OAB Projects\\development\\webservercert\\A2A\\sslkeystore.bin"));
//				keyStream = new FileInputStream(new File("/opt/ijtimaati/sslkeystore-MC.bin"));
				KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] keyPassword = keystorepass.trim().toCharArray();
				keyStore.load(keyStream, keyPassword);
				KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				keyFactory.init(keyStore, keyPassword);
				km = keyFactory.getKeyManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (keyStream != null) {
					keyStream.close();
					keyStream = null;
				}
			}
			FileInputStream trustStream = null;
			try {
				// trustStream = new FileInputStream(new
				// File("D:\\Sundaresh\\webserverproject\\config\\truststore.bin"));
				trustStream = new FileInputStream(new File("S:\\OAB Projects\\development\\webservercert\\A2A\\truststore.bin"));
//				trustStream = new FileInputStream(new File("/opt/ijtimaati/truststore-MC.bin"));
				KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] trustPassword = keystorepass.trim().toCharArray();
				trustStore.load(trustStream, trustPassword);
				TrustManagerFactory trustFactory = TrustManagerFactory
						.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				trustFactory.init(trustStore);
				tm = trustFactory.getTrustManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (trustStream != null) {
					trustStream.close();
					trustStream = null;
				}
			}
			sslContext.init(km, tm, null);
			javax.net.ssl.SSLSocketFactory sslFactory = sslContext.getSocketFactory();
			HttpsURLConnection.setDefaultSSLSocketFactory(sslFactory);
			sendURL = (HttpURLConnection) url.openConnection();
			requestMethod = requestMethod.toUpperCase();
			if (!requestMethod.equals("POST") && !requestMethod.equals("GET")) {
				return null;
			}
			sendURL.setRequestMethod(requestMethod);
			sendURL.setDoOutput(true);
			sendURL.setDoInput(true);
			sendURL.setAllowUserInteraction(false);
			if (contentType != null)
				sendURL.setRequestProperty("Content-Type", contentType);
			if (msg != null && msg.length > 0) {
				sendURL.setRequestProperty("Content-Length", String.valueOf(msg.length));
				out = new BufferedOutputStream(sendURL.getOutputStream());
				out.write(msg, 0, msg.length);
				out.flush();
				out.close();
			}
			if (noResponse)
				return null;
			int length = sendURL.getContentLength();
			byte bytes[];
			if (length < 0) {
				ByteArrayOutputStream bout = new ByteArrayOutputStream(128);
				in = new BufferedInputStream(sendURL.getInputStream());
				do {
					int b = in.read();
					if (b == -1)
						break;
					bout.write(b);
				} while (true);
				bytes = bout.toByteArray();
				return bytes;
			}
			bytes = new byte[length];
			in = new BufferedInputStream(sendURL.getInputStream());
			int pos;
			int numBytesRead;
			for (pos = 0; pos < length; pos += numBytesRead) {
				numBytesRead = in.read(bytes, pos, length - pos);
				if (numBytesRead != -1)
					continue;
				break;
			}
			return bytes;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (out != null) {
					try {
						out.close();
					} catch (Exception ex) {
					}
					out = null;
				}
				if (in != null) {
					try {
						in.close();
					} catch (Exception ex) {
					}
					in = null;
				}
			} catch (Exception e) {
			}
		}
		return null;
	}

	
	public byte[] connect(String hostURL, byte msg[], String requestMethod, String contentType,
			boolean noResponse) {
		URL url = null;
		BufferedOutputStream out = null;
		BufferedInputStream in = null;
		HttpURLConnection sendURL = null;
		try {
			try {
				url = new URL(hostURL.trim());
			} catch (MalformedURLException e) {
			}
			if (url == null) {
				return null;
			}
			KeyManager[] km = null;
			TrustManager[] tm = null;
			SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
			System.setProperty("javax.net.debug", "all");
			System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");
			FileInputStream keyStream = null;
			if(false) {
			String keystorepass = "changeit";
			try {
				// keyStream = new FileInputStream(new
				keyStream = new FileInputStream(new File("C:\\Program Files\\Java\\jdk1.8.0_201\\jre\\lib\\security\\cacerts"));
				KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] keyPassword = keystorepass.trim().toCharArray();
				keyStore.load(keyStream, keyPassword);
				KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				keyFactory.init(keyStore, keyPassword);
				km = keyFactory.getKeyManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (keyStream != null) {
					keyStream.close();
					keyStream = null;
				}
			}
			FileInputStream trustStream = null;
			try {
				// trustStream = new FileInputStream(new
				// File("D:\\Sundaresh\\webserverproject\\config\\truststore.bin"));
				trustStream = new FileInputStream(new File("S:\\OAB Projects\\development\\webservercert\\CBO\\truststore.bin"));
//				trustStream = new FileInputStream(new File("/opt/ijtimaati/truststore-MC.bin"));
				KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] trustPassword = keystorepass.trim().toCharArray();
				trustStore.load(trustStream, trustPassword);
				TrustManagerFactory trustFactory = TrustManagerFactory
						.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				trustFactory.init(trustStore);
				tm = trustFactory.getTrustManagers();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (trustStream != null) {
					trustStream.close();
					trustStream = null;
				}
			}
			sslContext.init(km, tm, null);
		
			javax.net.ssl.SSLSocketFactory sslFactory = sslContext.getSocketFactory();
			HttpsURLConnection.setDefaultSSLSocketFactory(sslFactory);
			}
			sendURL = (HttpURLConnection) url.openConnection();
			requestMethod = requestMethod.toUpperCase();
			if (!requestMethod.equals("POST") && !requestMethod.equals("GET")) {
				return null;
			}
			sendURL.setRequestMethod(requestMethod);
			sendURL.setDoOutput(true);
			sendURL.setDoInput(true);
			sendURL.setAllowUserInteraction(false);
			if (contentType != null)
				sendURL.setRequestProperty("Content-Type", contentType);
			if (msg != null && msg.length > 0) {
				sendURL.setRequestProperty("Content-Length", String.valueOf(msg.length));
				out = new BufferedOutputStream(sendURL.getOutputStream());
				out.write(msg, 0, msg.length);
				out.flush();
				out.close();
			}
			if (noResponse)
				return null;
			int length = sendURL.getContentLength();
			byte bytes[];
			if (length < 0) {
				ByteArrayOutputStream bout = new ByteArrayOutputStream(128);
				in = new BufferedInputStream(sendURL.getInputStream());
				do {
					int b = in.read();
					if (b == -1)
						break;
					bout.write(b);
				} while (true);
				bytes = bout.toByteArray();
				return bytes;
			}
			bytes = new byte[length];
			in = new BufferedInputStream(sendURL.getInputStream());
			int pos;
			int numBytesRead;
			for (pos = 0; pos < length; pos += numBytesRead) {
				numBytesRead = in.read(bytes, pos, length - pos);
				if (numBytesRead != -1)
					continue;
				break;
			}
			return bytes;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (out != null) {
					try {
						out.close();
					} catch (Exception ex) {
					}
					out = null;
				}
				if (in != null) {
					try {
						in.close();
					} catch (Exception ex) {
					}
					in = null;
				}
			} catch (Exception e) {
			}
		}
		return null;
	}

	
	public String testAmexCard() {
		String str = null;
		byte abyte0[] = null;
		String url = null;
		try {
			url = "https://stlds-safekey.americanexpress.com/";

			String messageId = new Date().getTime() + "";

			String VEREQ = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ThreeDSecure><Message id=\"" + messageId
					+ "\"><VEReq><version>1.0.2</version><pan>375987000000005</pan><Merchant><acqBIN>12345678901</acqBIN><merID>0000013705</merID></Merchant></VEReq></Message></ThreeDSecure>";

			System.out.println("VEREQ..." + VEREQ);
			abyte0 = sendMessage(url, VEREQ.getBytes(), "POST", "application/xml; charset=utf-8", false);
			str = new String(abyte0);
			System.out.println("VERES..." + str);
		} catch (Exception e) {
			for (int i = 0; i < e.getStackTrace().length; i++) {
				str = str + e.getStackTrace()[i] + "<br>";
			}
		}
		str = "Connecting... " + url + "<br>" + str;
		return str;
	}

	public static void main(String args[]) {
		HttpsConnection_Auth httpsconnection = null;
		try {
			httpsconnection = new HttpsConnection_Auth();
//			httpsconnection.testAmexCard();

//			httpsconnection.testAmexauth();

//			httpsconnection.testMasterCard();
			
			httpsconnection.testVisa3dsCard();
			
//			httpsconnection.testOmanNetCard();
			
//			httpsconnection.testA2ACard();
			
//			httpsconnection.testSecurePayment();
			
		} catch (Exception e) {
			e.printStackTrace();

		}

	}

	private String testVisa3dsCard() {
		String str = null;
		byte abyte0[] = null;
		String url = null;
		try {
			url = "https://VisaSecureTestSuite-vsts.3dsecure.net/ds2";
			String messageId = new Date().getTime() + "";
			System.setProperty("javax.net.debug", "all");
			System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");

			String aReq = "{\r\n" + 
					"	\"threeDSCompInd\": \"N\",\r\n" + 
					"	\"threeDSRequestorAuthenticationInd\": \"01\",\r\n" + 
					"	\"threeDSRequestorURL\": \"https://certpayments.oabipay.com/oabShoppingMerchant\",\r\n" + 
					"	\"threeDSServerTransID\": \"18b472-c5a8-4e4c-9364-0427a2aec10e\",\r\n" + 
					"	\"threeDSServerURL\": \"http://testing.oabipay.com:8080/componsate/rReq.htm\",\r\n" + 
					"	\"acquirerBIN\": \"473007\",\r\n" + 
					"	\"acquirerMerchantID\": \"3101550163500\",\r\n" + 
					"	\"browserIP\": \"0:0:0:0:0:0:0:1\",\r\n" + 
					"	\"browserJavaEnabled\": false,\r\n" + 
					"	\"browserJavascriptEnabled\": false,\r\n" + 
					"	\"cardExpiryDate\": \"2212\",\r\n" + 
					"	\"acctNumber\": \"4012001037490006\",\r\n" + 
					"	\"deviceChannel\": \"02\",\r\n" + 
					"	\"merchantCountryCode\": \"512\",\r\n" + 
					"	\"merchantName\": \"Oman Arab Bank Shopping\",\r\n" + 
					"	\"messageType\": \"AReq\",\r\n" + 
					"	\"messageVersion\": \"2.1.0\",\r\n" + 
					"	\"purchaseAmount\": \"100\",\r\n" + 
					"	\"purchaseCurrency\": \"512\",\r\n" + 
					"	\"purchaseExponent\": \"3\",\r\n" + 
					"	\"purchaseDate\": \"20220308143547\",\r\n" + 
					"	\"transType\": \"01\"\r\n" + 
					"}";

			
			System.out.println("AREQ..." + aReq);
			abyte0 = send3DsMessage(url, aReq.getBytes(), "POST", "application/json; charset=utf-8", false);
			str = new String(abyte0);
			System.out.println("ARES..." + str);
		} catch (Exception e) {
			for (int i = 0; i < e.getStackTrace().length; i++) {
				str = str + e.getStackTrace()[i] + "<br>";
			}
		}
		str = "Connecting... " + url + "<br>" + str;
		return str;
	}

	private String testAmexauth() {
		String requestStr = null;
		String[] resp = null;
		String url = null;
		String hostReq = null;
		String paymentId = null;
		String hdr_post = null;
		String hdr_host = null;
		String hdr_origin = null;
		String hdr_country = null;
		String hdr_region = null;
		String hdr_message = null;
		String hdr_mrchNbr = null;
		String hdr_rtInd = null;
		Map<String, String> headerMap = null;
		try {
			requestStr = "https://qwww318.americanexpress.com/IPPayments/inter/CardAuthorization.do||F1F1F0F0723424E008E08808F1F5F3F7F5F9F8F7F0F0F0F0F0F0F0F0F5F0F0F4F0F0F0F0F0F0F0F0F0F0F0F0F1F0F0F0F1F1F6F1F6F0F9F5F2F6F3F6F1F0F0F2F0F0F1F1F6F1F6F0F9F5F3F2F0F1F2F5F1F2F6F0F0F0E2F0E2F0F0F0F0F0F1F9F0F0F7F2F9F9F6F0F0F1F6F1F0F0F0F0F0F4F9F9F0F0F0F0F0F0F1F9F7F6F6F5F9F8F2F9F64040404040F3F7D6D4C1D540C1D9C1C240C2C1D5D240E2C8D6D7D7C9D5C7E0E0E040404040404040404040E0F5F1F2F0F4F1F2F3F1F0F5F4C1E7C1E2D2F0F5C1C5E5E50000010616212100000000000221210000000000E7C9C4C1F2D18D1A89150E059D26C77D4CA1FE953E4325||202001638272131||/IPPayments/inter/CardAuthorization.do HTTP/1.1||www359.americanexpress.com||OABOM||512||JAPA||ISO GCAG||9827915075||000";

			resp = requestStr.split("\\|\\|");
			url = resp[0];
			hostReq = resp[1];
			paymentId = resp[2];
			hdr_post = resp[3];
			hdr_host = resp[4];
			hdr_origin = resp[5];
			hdr_country = resp[6];
			hdr_region = resp[7];
			hdr_message = resp[8];
			hdr_mrchNbr = resp[9];
			hdr_rtInd = resp[10];

			headerMap = new LinkedHashMap<String, String>();

			headerMap.put("post", hdr_post);
			headerMap.put("host", hdr_host);
			headerMap.put("origin", hdr_origin);
			headerMap.put("country", hdr_country);
			headerMap.put("region", hdr_region);
			headerMap.put("message", hdr_message);
			headerMap.put("mrchNbr", hdr_mrchNbr);
			headerMap.put("rtInd", hdr_rtInd);
			sendAmexMessage(url, hostReq, headerMap);
			System.out.println("HttpsConnection.testAmexauth() ::  End");

		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}

	public static String sendAmexMessage(String hostURL, String msg, Map<String, String> headerMap) {
		String str = null;
		StringBuffer stfBuf = null;
		DataOutputStream serviceDataOutputStream = null;
		BufferedReader inRead = null;
		String amexTimeOutFlg = null;
		URL url;
		HttpsURLConnection sendURL = null;
		try {
			System.setProperty("javax.net.debug", "all");
			try {
				url = new URL(hostURL.trim());
			} catch (MalformedURLException e) {
				try {
					stfBuf = null;
					str = null;
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				return null;
			}

			
			sendURL = (HttpsURLConnection) url.openConnection();
			sendURL.setRequestProperty("POST", (String) headerMap.get("post"));
			sendURL.setRequestProperty("Accept-Language", "en-us");
			sendURL.setRequestProperty("Content-Type", "plain/text");
			sendURL.setRequestProperty("User-Agent", "Application");

			sendURL.setRequestProperty("Host", (String) headerMap.get("host"));
			sendURL.setRequestProperty("Cache-Control", "no-cache");
			sendURL.setRequestProperty("Connection", "Keep-Alive");

			sendURL.setRequestProperty("origin", (String) headerMap.get("origin"));

			sendURL.setRequestProperty("country", (String) headerMap.get("country"));

			sendURL.setRequestProperty("region", (String) headerMap.get("region"));

			sendURL.setRequestProperty("message", (String) headerMap.get("message"));

			sendURL.setRequestProperty("MerchNbr", (String) headerMap.get("mrchNbr"));

			sendURL.setRequestProperty("RtInd", (String) headerMap.get("rtInd"));

			amexTimeOutFlg = "N";

			if ((amexTimeOutFlg != null) && ("Y".equalsIgnoreCase(amexTimeOutFlg.trim()))) {
				sendURL.setConnectTimeout(6 * 1000);
				sendURL.setReadTimeout(6 * 1000);
			}

			sendURL.setConnectTimeout(Integer.parseInt("30".trim()) * 1000);
			sendURL.setReadTimeout(Integer.parseInt("30".trim()) * 1000);

			sendURL.setDoInput(true);
			sendURL.setDoOutput(true);
			sendURL.setUseCaches(false);

			msg = "AuthorizationRequestParam=" + msg;

			int queryLength = msg.length();
			sendURL.setRequestProperty("Content-Length", String.valueOf(queryLength));

			serviceDataOutputStream = new DataOutputStream(sendURL.getOutputStream());
			serviceDataOutputStream.writeBytes(msg);
			serviceDataOutputStream.flush();
			serviceDataOutputStream.close();

			int length = sendURL.getContentLength();

			inRead = new BufferedReader(new InputStreamReader(sendURL.getInputStream()));

			stfBuf = new StringBuffer();
			while ((str = inRead.readLine()) != null) {
				stfBuf.append(str);
			}
			String str1 = stfBuf.toString();
			System.out.println(str1);
			return str1;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} finally {
			try {
				if (serviceDataOutputStream != null) {
					serviceDataOutputStream.close();
					serviceDataOutputStream = null;
				}
				if (inRead != null) {
					inRead.close();
					inRead = null;
				}
				if (sendURL != null) {
					sendURL.disconnect();
					sendURL = null;
				}
				stfBuf = null;
				str = null;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static void disableSSLVerification() {

		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				// TODO Auto-generated method stub

			}

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				// TODO Auto-generated method stub

			}
		} };

		SSLContext sc = null;
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
		} catch (KeyManagementException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		HostnameVerifier allHostsValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};
		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
	}
}