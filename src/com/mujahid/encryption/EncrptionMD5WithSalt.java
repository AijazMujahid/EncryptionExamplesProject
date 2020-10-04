package com.mujahid.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class EncrptionMD5WithSalt {

	public static void main(String[] args) throws NoSuchAlgorithmException,NoSuchProviderException {
		String passwordToHash = "password";
		byte[] salt = getSalt();
		
		String securePassword = getSecurePassword(passwordToHash,salt);
		System.out.println("First Attempt : "+securePassword);
		
		String regeneratedPasswordToVerify = getSecurePassword(passwordToHash,salt);
		System.out.println("Second Attempt : "+regeneratedPasswordToVerify);
	}
	
	private static String getSecurePassword(String passwordToHash, byte[] salt) {
		String generatedPassword = null;
		try {
			//create MD Digest 
			MessageDigest md = MessageDigest.getInstance("MD5");
			//add password bytes to digest 
			md.update(salt);
			//get the hash bytes
			byte[] bytes = md.digest(passwordToHash.getBytes());
			//this bytes has been in decimal format 
			//convert them into hexa decimal format 
			StringBuilder sb = new StringBuilder();
			for(int i=0;i<bytes.length;i++) {
				sb.append(Integer.toString((bytes[i] & 0xff)+ 0x100, 16).substring(1));
			}
			//get complete hashed password in hex format 
			generatedPassword = sb.toString();
		}catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatedPassword;
	}
	
	//salting example (SecureRandom is used to generate salt for hash)
	private static byte[] getSalt() throws NoSuchAlgorithmException{
	//always use secure random generator
	SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
	//create array for salt
	byte[] salt = new byte[16];
	//get a random salt
	sr.nextBytes(salt);
	return salt;
	}		
	
	
}
