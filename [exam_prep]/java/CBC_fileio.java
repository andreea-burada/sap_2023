package ro.ase.ism.sap.day3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CipherCBC {
	public static void encrypt(
			String filename, 
			String cipherFilename, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV is known/generated and placed in the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(cipherFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
		
		//IV has the 5th byte from left to right all bits 1
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[4] = (byte) 0xFF;
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		//write the IV in the file
		fos.write(IV);
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}
	
	public static void decrypt(
			String filename, 
			String outputFile, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File outFile = new File(outputFile);
		if(!outFile.exists()) {
			outFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
		
		//getting the IV from the file
		byte[] IV = new byte[cipher.getBlockSize()];
		fis.read(IV);
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {
		//test CBC
		CipherCBC.encrypt("msg.txt", "msgCBC.enc", "password12345678", "AES");
		CipherCBC.decrypt("msgCBC.enc", "msg3.txt", "password12345678", "AES");
		
		System.out.println("Done.");
	}
}
