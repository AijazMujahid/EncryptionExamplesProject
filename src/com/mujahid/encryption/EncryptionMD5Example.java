package com.mujahid.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EncryptionMD5Example {

	public static void main(String[] args) throws Exception {
		
		String passwordToHash = "password";
		String generatedPassword = null;
		try {
			//create message digest instance for MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			System.out.println("md instance : "+md);
			System.out.println("passwordToHash : "+passwordToHash);
			//add password bytes to digest
			md.update(passwordToHash.getBytes());
			//get hash bytes 
			byte[] bytes = md.digest();
			System.out.println("bytes : "+bytes);
			//this bytes has bytes in decimal format
			//convert into hexadecimal format
			StringBuilder sb = new StringBuilder();
			System.out.print("0xff : "+Integer.toString(0xff)+"\t");
			System.out.print("0x100 : "+Integer.toString(0x100)+"\n");
			for(int i=0;i<bytes.length;i++) {			
				System.out.print("bytes["+i+"] : "+bytes[i]+"\t");
				//0xff is an int literal (the & operation with 0xff prefix zeroes in the hex format to give a proper int value)
				System.out.print(Integer.toString(bytes[i] & 0xff)+"\t"); 
				System.out.print(Integer.toString(bytes[i] & 0xff) + 0x100 +"\t");
				System.out.print(Integer.toString((bytes[i] & 0xff)+ 0x100, 16)+"\n");
				sb.append(Integer.toString((bytes[i] & 0xff)+ 0x100, 16)).substring(i); //eg. 95 + 256 = 351 which is 1-5-F (15F)
			}
			//get complete hashed password in hexadecimal format
			generatedPassword = sb.toString();
			System.out.println("MD5 Encrypted Password :"+generatedPassword);	
			
		}	catch(NoSuchAlgorithmException e ) {
			e.printStackTrace();
		}
		
		
	}

	
}
