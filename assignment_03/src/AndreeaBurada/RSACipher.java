package AndreeaBurada;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;

public class RSACipher {
    public static byte[] encrypt(
            Key key,
            byte[] input
    ) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }
    public static boolean hasValidSignature (
            String filename,
            PublicKey key,
            String signatureFileName
    ) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        File file = new File(filename);
        File signatureFile = new File(signatureFileName);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }
        if(!signatureFile.exists()) {
            throw new FileNotFoundException();
        }

        FileInputStream fis = new FileInputStream(file);
        byte[] fileContent = fis.readAllBytes();
        fis.close();
        fis = new FileInputStream(signatureFile);
        byte[] signature = fis.readAllBytes();

        Signature signatureModule = Signature.getInstance("SHA512withRSA");
        signatureModule.initVerify(key);

        signatureModule.update(fileContent);
        return signatureModule.verify(signature);
    }

    public static byte[] signFile (
            String filename,
            PrivateKey key
    ) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        File file = new File(filename);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(file);

        byte[] fileContent = fis.readAllBytes();

        fis.close();

        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(key);

        signature.update(fileContent);
        return signature.sign();
    }
}
