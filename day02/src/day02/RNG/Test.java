package day02.RNG;

import day02.Hash.Hash;
import day02.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.naming.OperationNotSupportedException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, OperationNotSupportedException, IOException, NoSuchProviderException {
        // test if a provider is available
        String providerName = "SunEC";

        Provider provider = Security.getProvider(providerName);
        if(provider != null) {
            System.out.println(provider.getName() + " is available.");
        }

        // load a provider at runtime - BouncyCastle
        if(provider == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // test the Secure Random
        byte[] randomBytes = RandomGenerator.getSecureRandom(16);
        System.out.println("\nSecure random bytes:");
        System.out.println(Utils.getHexString(randomBytes));

        byte[] seed = {0x01, 0x02, 0x03};
        randomBytes = RandomGenerator.getSecureRandom(16, seed);
        System.out.println("\nSecure random bytes with seed:");
        System.out.println(Utils.getHexString(randomBytes));

        // MD5
        byte[] hash = Hash.getMessageDigest("Stop joc. Final apoteotic.");
        System.out.println("\nSHA-1 Hash:");
        System.out.println(Utils.getHexString(hash));

        byte[] fileHash = Hash.getFileMessageDigest("message.txt", "SHA-1", "BC");
        System.out.println("\nFile MD5:");
        System.out.println(Utils.getHexString(fileHash));
    }
}
