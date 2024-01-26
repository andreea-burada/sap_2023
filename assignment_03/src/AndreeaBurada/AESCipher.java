package AndreeaBurada;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AESCipher {
    public static byte[] generateKey(int noBytes) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator =
                KeyGenerator.getInstance("AES");
        keyGenerator.init(noBytes);
        return keyGenerator.generateKey().getEncoded();
    }

    public static void encrypt(
            String plaintextFileName,
            String ciphertextFileName,
            byte[] password
    ) throws IOException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {

        File inputFile = new File(plaintextFileName);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File cipherFile = new File(ciphertextFileName);
        if(!cipherFile.exists()) {
            cipherFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(cipherFile);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(password, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        //get the last ciphertext block
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }
}
