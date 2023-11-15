package day03;

import day03.HMAC.HMAC;
import day03.PBKDF.PBKDF;
import day03.utils.Utils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException {
        // test hmac
        byte[] hmacValue = HMAC.getHMAC("This is a secret !", "1234", "HmacSHA256");
        System.out.println("HMAC:");
        System.out.println(Utils.getHexString(hmacValue));

        hmacValue = HMAC.getFileHMAC("msg.txt", "Salt mortal", "HmacMD5");
        System.out.println("HMAC file:");
        System.out.println(Utils.getHexString(hmacValue));

        // test pbkdf
        byte[] saltedHash = PBKDF.getPBKDF("12345678", "PBKDF2WithHmacSHA256", "ism", 100);
        System.out.println("Salted hash of 12345678: ");
        System.out.println(Utils.getHexString(saltedHash));

        // benchmark sha2 vs PBKDF2WithHmacSHA256
        double tStart = System.nanoTime();
        byte[] hashValue = Hash.getHash("12345678", "SHA-256");
        double tEnd = System.nanoTime();
        System.out.printf("\nSHA-256: Done in: %.2f nanoseconds", tEnd - tStart);

        tStart = System.nanoTime();
        saltedHash = PBKDF.getPBKDF("12345678", "PBKDF2WithHmacSHA256", "ism", 100);
        tEnd = System.nanoTime();
        System.out.printf("\nPBKDF: Done in: %.2f nanoseconds", tEnd - tStart);
    }
}
