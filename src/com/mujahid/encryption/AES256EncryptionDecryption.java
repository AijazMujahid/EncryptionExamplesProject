package com.mujahid.encryption;

import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES256EncryptionDecryption {
	
	private static String secretKey = "HondaCity2020ORVernaANDNewJobWith12LPA";
	private static String salt = "aijazmujahid0831";
	
	public static String encrypt(String strToEncrypt,String secret) {
		try {
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivspec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		}catch(Exception e ) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}
	
	public static String decrypt(String strToDecrypt, String secret) {
	    try
	    {
	        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	        IvParameterSpec ivspec = new IvParameterSpec(iv);
	         
	        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
	        SecretKey tmp = factory.generateSecret(spec);
	        SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
	         
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
	        return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
	    } 
	    catch (Exception e) {
	        System.out.println("Error while decrypting: " + e.toString());
	    }
	    return null;
	}

	public static void main(String[] args) {

		String originalString = "password";
		
		String encryptedString = AES256EncryptionDecryption.encrypt(originalString,secretKey); 
		String decryptedString = AES256EncryptionDecryption.decrypt(encryptedString, secretKey);
		
		 System.out.println(originalString);
		 System.out.println(encryptedString);
		 System.out.println(decryptedString);

	}

}


/* Program execution failed and found this on stack overflow to resolve this issue
 * Most likely you don't have the unlimited strength file installed now.
 * 
 * Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy
 * Files 8 Download
 * 
 * Extract the jar files from the zip and save them in
 * ${java.home}/jre/lib/security/
 */
