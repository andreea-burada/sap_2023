package day03.OTP;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

// do we need a seed?
// do we need to continue generating the sequence? (if you have a seed -> yes)
public class KeyGenerator {
    private byte[] seed;
    private String algorithm;
    SecureRandom secureRandom = null;

    public KeyGenerator(byte[] seed, String algorithm) {
        super();
        this.seed = seed;
        this.algorithm = algorithm;
    }

    public byte[] getRandomBytes(int noBytes) throws NoSuchAlgorithmException {
        if(secureRandom == null) {
            secureRandom = SecureRandom.getInstance(this.algorithm);
            secureRandom.setSeed(this.seed);
        }

        byte[] random = new byte[noBytes];
        secureRandom.nextBytes(random);
        return random;
    }
}
