package ro.ase.ism.sap.day3;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF {
	public static byte[] getPBKDF(
			String userPassword, 
			String algorithm,
			String salt,
			int noIterations
			) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		SecretKeyFactory pbkdf = 
				SecretKeyFactory.getInstance(algorithm);
		PBEKeySpec pbkdfSpecifications = 
				new PBEKeySpec(
						userPassword.toCharArray(), 
						salt.getBytes(), 
						noIterations,256);
		SecretKey secretKey = pbkdf.generateSecret(pbkdfSpecifications);
		return secretKey.getEncoded();
		
	}

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		// test pbkdf
		
		byte[] saltedHash = PBKDF.getPBKDF("12345678", 
				"PBKDF2WithHmacSHA256", "ism", 100);
		System.out.println("Salted hash of 12345678: ");
		System.out.println(Util.getHexString(saltedHash));
		
		//benchmark sha2 vs BKDF2WithHmacSHA256
		
		double tStart = System.currentTimeMillis();
		byte[] hashValue = Hash.getHash("12345678", "SHA-256");
		double tEnd = System.currentTimeMillis();
		
		System.out.println("SHA2 of 12345678 is ");
		System.out.println(Util.getHexString(hashValue));
		System.out.println(String.format(
				"Done in %f millis", tEnd - tStart));
		

		tStart = System.currentTimeMillis();
		saltedHash = PBKDF.getPBKDF("12345678", 
				"PBKDF2WithHmacSHA256", "ism", 15000);
		tEnd = System.currentTimeMillis();
		
		System.out.println("PBKFD SHA2 of 12345678 is ");
		System.out.println(Util.getHexString(saltedHash));
		System.out.println(String.format(
				"Done in %f millis", tEnd - tStart));
	}
}
