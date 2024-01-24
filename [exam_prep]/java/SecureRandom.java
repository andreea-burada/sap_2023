package ro.ase.ism.sap.day2;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class RandomGenerator {
	
	//never do this - never use Random
	public static byte[] getRandom(int size) {
		Random random = new Random();
		byte[] notRandomBytes = new byte[size];		
		random.nextBytes(notRandomBytes);
		return notRandomBytes;
	}
	
	public static byte[] getSecureRandom(int size) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] randomBytes = new byte[size];
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}
	
	public static byte[] getSecureRandom(int size, byte[] seed) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		secureRandom.setSeed(seed);
		byte[] randomBytes = new byte[size];
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		//test the Secure Random
		byte[] randomBytes = RandomGenerator.getSecureRandom(16);
		System.out.println("Secure random bytes");
		System.out.println(Util.getHexString(randomBytes));
		
		byte[] seed = {0x01, 0x02, 0x03};
		randomBytes = RandomGenerator.getSecureRandom(16, seed);
		System.out.println("Secure random bytes");
		System.out.println(Util.getHexString(randomBytes));
	}

}
