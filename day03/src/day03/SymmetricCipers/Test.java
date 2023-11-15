package day03.SymmetricCipers;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Test {
    public static void main(String[] args) throws NoSuchPaddingException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // 64 bit key - 8 char. long password for DES
        ECB.encrypt("msg.txt", "msg.enc", "12345678", "DES");

        // example with a 256 bits key but with a block size of 128 bits

        System.out.println("Done");
    }
}
