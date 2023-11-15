package day03.SymmetricCipers;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class CBC {
    public static void encrypt(
            String inputFilename,
            String cipherFilename,
            String password,
            String algorithm
    ) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // IV is known/generated and placed in the cipher file at the beginning

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

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");

        // IV has the 5th byte from left to right all 1s
        byte[] IV = new byte[cipher.getBlockSize()];
        IV[4] = (byte) 0xFF;


        SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

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
