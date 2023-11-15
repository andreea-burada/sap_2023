package day03.OTP;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class Test {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        String secretSeed = "randomEY1234";
        KeyGenerator keyGen = new KeyGenerator(
                secretSeed.getBytes(),
                "Windows-PRNG");
        OTP.encryptFile("otv.txt", "otv.enc", "secretkey.key", keyGen);
        OTP.decryptFile("otv.otp", "secretkey.key", "msg2.txt");
    }
}
