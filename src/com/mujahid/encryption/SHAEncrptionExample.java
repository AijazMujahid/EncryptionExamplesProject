package com.mujahid.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/*Different SHA Algorithms
MessageDigest md1 = MessageDigest.getInstance("SHA-1");
MessageDigest md2 = MessageDigest.getInstance("SHA-256");
MessageDigest md3 = MessageDigest.getInstance("SHA-384");
MessageDigest md4 = MessageDigest.getInstance("SHA-512");*/

public class SHAEncrptionExample {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		
	String originalPassword = "password"; 
	System.out.println("Original Password : "+originalPassword);
	
	String[] SHATypeAlgoritm = {"SHA-1","SHA-256","SHA-384","SHA-512"} ;
	
	for(int i=0;i<SHATypeAlgoritm.length;i++) {
	System.out.println("Encrypted password using "+SHATypeAlgoritm[i]+" : "
			+get_SHA_securePassword(originalPassword, getSalt(),SHATypeAlgoritm[i]));	
		}

	}
	
	private static String get_SHA_securePassword(String passwordToHash,byte[] salt,String SHAType) {
		String generatePassword = null;
		try {
			MessageDigest md1 = MessageDigest.getInstance(SHAType);
			md1.update(salt);
			byte[] bytes1 = md1.digest(passwordToHash.getBytes());
			StringBuilder sb1 = new StringBuilder();
			for(int i=0;i<bytes1.length;i++) {
				sb1.append(Integer.toString((bytes1[i] & 0xff) + 0x100, 16)).substring(1);
			}
			generatePassword = sb1.toString();
		}catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatePassword;
	}
	
	
	private static byte[] getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt;
	}

}
