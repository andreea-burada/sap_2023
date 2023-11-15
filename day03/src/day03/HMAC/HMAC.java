package day03.HMAC;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class HMAC {
    public static byte[] getHMAC(
            String input,
            String secret,
            String algorithm
    ) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance(algorithm);
        Key hmacKey = new SecretKeySpec(secret.getBytes(), algorithm);
        hmac.init(hmacKey);

        return hmac.doFinal(input.getBytes());
    }

    public static byte[] getFileHMAC(
            String filename,
            String secret,
            String algorithm
    ) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        // handling the file at byte level
        File file = new File(filename);
        if(!file.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }

        FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis);

        Mac hmac = Mac.getInstance(algorithm);
        Key hmacKey = new SecretKeySpec(secret.getBytes(), algorithm);
        hmac.init(hmacKey);

        byte[] buffer = new byte[16];
        int noBytes = 0;

        while(noBytes != -1) {
            noBytes = bis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            hmac.update(buffer, 0, noBytes);
        }

        return hmac.doFinal();
    }
}
