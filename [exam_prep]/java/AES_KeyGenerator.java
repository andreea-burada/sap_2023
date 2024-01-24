package ro.ase.ism.sap.day4;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;

public class AESCipher {

	public static byte[] generateKey(int noBytes) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = 
				KeyGenerator.getInstance("AES");
		keyGenerator.init(noBytes);
		return keyGenerator.generateKey().getEncoded();
	}
	
	// byte[] randomAESKey = AESCipher.generateKey(128);
	// System.out.println("AES Random key: ");
	// System.out.println(getHexString(randomAESKey));
}
