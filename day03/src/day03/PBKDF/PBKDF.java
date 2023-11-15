package day03.PBKDF;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBKDF {
    public static byte[] getPBKDF(
            String userPassword,
            String algorithm,
            String salt,
            int noIterations
    ) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance(algorithm);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(
                userPassword.toCharArray(),
                salt.getBytes(),
                noIterations,
                256);
        SecretKey secretKey = pbkdf.generateSecret(pbeKeySpec);

        return secretKey.getEncoded();
    }
}
