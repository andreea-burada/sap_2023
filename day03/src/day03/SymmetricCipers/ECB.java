package day03.SymmetricCipers;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ECB {
    public static void encrypt(
            String inputFilename,
            String cipherFilename,
            String password,
            String algorithm
    ) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File inputFile = new File(inputFilename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file!");
        }
        File cipherFile = new File(cipherFilename);
        if(!cipherFile.exists()) {
            cipherFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(cipherFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            // cipher.update(buffer); NO!
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        byte[] finalBlock = cipher.doFinal();
        fos.write(finalBlock);
    }
}
