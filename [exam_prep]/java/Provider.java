package ro.ase.ism.sap.day2;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Test {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		//test if a provider is available
		
		//String providerName = "SUN";
		String providerName = "BC";
		
		Provider provider = Security.getProvider(providerName);
		if(provider != null) {
			System.out.println(providerName + " is available");
		} else {
			System.out.println(providerName + " is NOT available");
		}
		
		
		//load a provider at runtime - BouncyCastle
		if(provider == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		
		provider = Security.getProvider(providerName);
		if(provider != null) {
			System.out.println(providerName + " is available");
		} else {
			System.out.println(providerName + " is NOT available");
		}
	}
	
}