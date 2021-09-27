package com.gxa.myapplication;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PemTlsDemo {
	
	private static final String VEHICLE_CRT_PATH = "C:\\Users\\Administrator\\Desktop\\pem-demo\\file\\vehicleCA.crt";
	private static final String VEHICLE_KEY_PATH = "C:\\Users\\Administrator\\Desktop\\pem-demo\\file\\vehicleCA.key";
	private static final String VEHICLE_KEY_PWD = "53A070BD720A2D9ED38EDA72C3EBE854A2AEE92B";
	private static final String ROOT_CRT_PATH = "C:\\Users\\Administrator\\Desktop\\pem-demo\\file\\rootCA.crt";
	
	private static String API_URL = "https://xxx.xxx.com";
	
	private static final String OPENSSL_ENCRYPTED_RSA_PRIVATEKEY_REGEX = "\\s*" 
			+ "-----BEGIN RSA PRIVATE KEY-----" + "\\s*"
			+ "Proc-Type: 4,ENCRYPTED" + "\\s*"
			+ "DEK-Info:" + "\\s*([^\\s]+)" + "\\s+"
			+ "([\\s\\S]*)"
			+ "-----END RSA PRIVATE KEY-----" + "\\s*";
	private static final Pattern OPENSSL_ENCRYPTED_RSA_PRIVATEKEY_PATTERN = Pattern.compile(OPENSSL_ENCRYPTED_RSA_PRIVATEKEY_REGEX);
	
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());

		try {
			String pemContents = readVehicleKey(VEHICLE_KEY_PATH);
			Matcher matcher = OPENSSL_ENCRYPTED_RSA_PRIVATEKEY_PATTERN.matcher(pemContents);
			if(matcher.matches()) {
				String encryptionDetails = matcher.group(1).trim();
				System.out.println("encryptionDetails:" + encryptionDetails);
				String[] encryptionDetailsParts = encryptionDetails.split(",");
				if (encryptionDetailsParts.length == 2) {
					
					String encryptionAlgorithm = encryptionDetailsParts[0];
			        String encryptedAlgorithmParams = encryptionDetailsParts[1];
			        
			        String encryptedKey = matcher.group(2).replaceAll("\\s", "");
					System.out.println("encryptedKey:" + encryptedKey);
			        byte[] encryptedBinaryKey =java.util.Base64.getDecoder().decode(encryptedKey);
					
					byte[] vehicleKeyPWD = new String(VEHICLE_KEY_PWD).getBytes(StandardCharsets.UTF_8);
					byte[] iv = fromHex(encryptedAlgorithmParams);
				    /*=======================--start--计算出加密密钥============================*/
					MessageDigest digest = MessageDigest.getInstance("MD5");// 注：openssl默认采用
				    digest.update(vehicleKeyPWD);
				    digest.update(iv, 0, 8);// 第一轮,摘要基于密码和iv的前8字节
				    
				    byte[] round1Digest = digest.digest();
				    
				    digest.update(round1Digest);
				    digest.update(vehicleKeyPWD);
				    digest.update(iv, 0, 8);// 第二轮,基于第一轮摘要、密码和IV的前8字节的第二轮摘要
				     
				    byte[] round2Digest = digest.digest();
				    
				    /*=======================--end--计算出加密密钥============================*/

			        Cipher cipher = null;
			        SecretKey secretKey = null;
			        byte[] key = null;
			        if ("AES-256-CBC".equals(encryptionAlgorithm)) {
			        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			            key = new byte[32]; // 256位密钥（块大小仍为128位）,密钥大小为32字节
			            System.arraycopy(round1Digest, 0, key, 0, 16);
			            System.arraycopy(round2Digest, 0, key, 16, 16);

			            secretKey = new SecretKeySpec(key, "AES");
			            
			        }else if ("AES-192-CBC".equals(encryptionAlgorithm)) {
			        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			            key = new byte[24]; // 192位密钥，密钥大小为24字节
			            System.arraycopy(round1Digest, 0, key, 0, 16);
			            System.arraycopy(round2Digest, 0, key, 16, 8);
			            
			        }else if ("AES-128-CBC".equals(encryptionAlgorithm)) {
			        	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			            key = new byte[16]; //128位密钥，大小为16个字节
			            System.arraycopy(round1Digest, 0, key, 0, 16);

			            secretKey = new SecretKeySpec(key, "AES");
			            
			        } else if ("DES-EDE3-CBC".equals(encryptionAlgorithm)) {
			        	 cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

			             key = new byte[24]; //该算法类型密钥大小为24个字节
			             System.arraycopy(round1Digest, 0, key, 0, 16);
			             System.arraycopy(round2Digest, 0, key, 16, 8);

			             secretKey = new SecretKeySpec(key, "DESede");
			        } else if ("DES-CBC".equals(encryptionAlgorithm)) {
			        	cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

			            key = new byte[8]; //该算法类型密钥长度为8个字节
			            System.arraycopy(round1Digest, 0, key, 0, 8);

			            secretKey = new SecretKeySpec(key, "DES");
			        }

				    cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
				    byte[] pkcs1 = cipher.doFinal(encryptedBinaryKey);//解密出证书私钥
				     
				    PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs1); 
				    KeyFactory keyFactory = KeyFactory.getInstance("RSA");  
				     
				    PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);//构造私钥对象
			        System.out.println("构造私钥对象成功，私钥信息："  + privateKey);

				    //读取车端证书,公钥
				    String vehicleCrt = readVehicleCA(VEHICLE_CRT_PATH);
				    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
				     
				    ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(vehicleCrt));
					X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(bais);
			        Certificate[] certificates = new Certificate[]{x509Certificate};

				    char[] keyStorepwd = "123456".toCharArray();	//构造keyStore对象，需要设定的密码，该密码可以任意设置

				    /*=======================--start--构造客户端证书的KeyStore============================*/
				    KeyStore clientCertKeyStore = KeyStore.getInstance("BKS", new BouncyCastleProvider());
				    clientCertKeyStore.load(null, keyStorepwd);
			        String keyAlias = "vehicleCA";
			        clientCertKeyStore.setKeyEntry(keyAlias, privateKey, keyStorepwd, certificates);
			        
			        System.out.println("构造客户端证书的KeyStore成功!~" );
			        /*=======================--end--构造客户端证书的KeyStore============================*/
			        
			        //读取根证书链
			        Map<String, String> rootMap = readRootCA(ROOT_CRT_PATH);
			        String root1 = rootMap.get("root1");
			        String root2 = rootMap.get("root2");
			        
			        ByteArrayInputStream trust1Bais = new ByteArrayInputStream(Base64.decodeBase64(root1));
			        X509Certificate trust1X509Certificate = (X509Certificate) certificateFactory.generateCertificate(trust1Bais);

			        ByteArrayInputStream trust2Bais = new ByteArrayInputStream(Base64.decodeBase64(root2));
			        X509Certificate trust2X509Certificate = (X509Certificate) certificateFactory.generateCertificate(trust2Bais);
			        
			        /*=======================--start--构造可信服务端证书的KeyStore============================*/
			        KeyStore trustKeyStore = KeyStore.getInstance("BKS", new BouncyCastleProvider());
				    trustKeyStore.load(null, keyStorepwd);
				    trustKeyStore.setCertificateEntry("root1", trust1X509Certificate);
				    trustKeyStore.setCertificateEntry("root2", trust2X509Certificate);
				    System.out.println("构造可信服务端证书的KeyStore成功!~" );
			        /*=======================--end--构造可信服务端证书的KeyStore============================*/
				    
				    /*=======================--start--双向认证示例============================*/
				    SSLContext sslcontext = SSLContexts.custom()
			        		.loadTrustMaterial(trustKeyStore, new TrustStrategy(){
			        			public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			        				return true;
			        			}})
			        		.loadKeyMaterial(clientCertKeyStore, keyStorepwd)
			        		.build();
			        
			        SSLConnectionSocketFactory sslConnectionSocketFactory  = new SSLConnectionSocketFactory(
			                sslcontext,
			                new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"},// 协议
			                null,
			                SSLConnectionSocketFactory.getDefaultHostnameVerifier());
			        
			        CloseableHttpClient httpClient = HttpClients.custom()
			        		.setSSLSocketFactory(sslConnectionSocketFactory)
			        		.build();

//					List<NameValuePair> parameters = new ArrayList<NameValuePair>();
//				
//					HttpPost httpPost = new HttpPost(API_URL);
//					httpPost.setEntity(new UrlEncodedFormEntity(parameters,Charset.forName("UTF-8")));
//					
//					httpPost.setHeader("Content-AppKey", ""); 
//					httpPost.setHeader("Content-Signature","" );
//					httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");
//					CloseableHttpResponse response = httpClient.execute(httpPost);
//					
//					int status = response.getStatusLine().getStatusCode();
//					System.out.println("通讯返回状态码："+status);
				    /*=======================--end--双向认证示例============================*/
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	public static byte[] fromHex(String hexString)	{
	    byte[] bytes = new byte[hexString.length() / 2];
	    for (int i = 0; i < hexString.length(); i += 2) {
	        bytes[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
	    }
	    return bytes;
	}
	
	public static String readVehicleKey(String filePath) {
		String pemStr = "";
        try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(filePath), "UTF-8"));
            String lineStr = null;
            while((lineStr=bufferedReader.readLine())!=null){
            	pemStr+= lineStr+"\r\n";
            }
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return pemStr;
	}
	
	public static String readVehicleCA(String filePath) {
		String pemStr = "";
        try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(filePath), "UTF-8"));
            String lineStr = null;
            while((lineStr=bufferedReader.readLine())!=null){
            	if(lineStr.length()== 0 || lineStr.indexOf(": ")>=0 || lineStr.indexOf("-----BEGIN")>=0 || lineStr.indexOf("-----END")>=0 ) {
            		continue;
            	}
            	pemStr+= lineStr.replace("\t", "");
            }
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return pemStr;
	}
	
	public static Map<String, String> readRootCA(String filePath) {
		Map<String, String>  retMap = new HashMap<String, String>();
		String root1Str = "";
		String root2Str = "";
		int bolCount = 0;
        try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(filePath), "UTF-8"));
            String lineStr = null;
            while((lineStr=bufferedReader.readLine())!=null){
            	if(lineStr.length()== 0 ) {
            		continue;
            	}
            	if(lineStr.indexOf("-----BEGIN")>=0) {
            		bolCount ++ ;
            		continue;
            	}
            	if(lineStr.indexOf("-----END")>=0 ) {
            		continue;
            	}
            	
            	if(bolCount<=1) {
            		root1Str+= lineStr.replace("\t", "");
            	}else {
            		root2Str+= lineStr.replace("\t", "");
            	}
            }
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
        
        retMap.put("root1", root1Str);
        retMap.put("root2", root2Str);

		return retMap;
	}
}
