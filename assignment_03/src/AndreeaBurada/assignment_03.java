package AndreeaBurada;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class assignment_03 {
    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value) {
            result.append(String.format("%02X ", b));
        }
        return result.toString();
    }
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, KeyStoreException, UnrecoverableKeyException {
        // get certificate from SimplePGP_ISM.cer
        PublicKey ismCertificate = Certificate.getPublicKeyFromCertificate("SimplePGP_ISM.cer");
//        System.out.println(ismCertificate);

        // check all files
        System.out.printf("SAPExamSubject1.txt is%s the original file\n",
                RSACipher.hasValidSignature("SAPExamSubject1.txt", ismCertificate, "SAPExamSubject1.signature") ? "" : " not");
        System.out.printf("SAPExamSubject2.txt is%s the original file\n",
                RSACipher.hasValidSignature("SAPExamSubject2.txt", ismCertificate, "SAPExamSubject2.signature") ? "" : " not");
        System.out.printf("SAPExamSubject3.txt is%s the original file\n",
                RSACipher.hasValidSignature("SAPExamSubject3.txt", ismCertificate, "SAPExamSubject3.signature") ? "" : " not");

        // generate random AES key
        byte[] aesKey = AESCipher.generateKey(128);
        System.out.println(getHexString(aesKey));
        // encrypt the key with the professor public key
        byte[] encryptedAesKey = RSACipher.encrypt(ismCertificate, aesKey);
        System.out.println(getHexString(encryptedAesKey));
        // write key to file
        FileOutputStream fos = new FileOutputStream(new File("aes_key.sec"));
        fos.write(encryptedAesKey);
        fos.close();

        // encrypt the message file MessageToProfessor.txt in ECB mode
        AESCipher.encrypt("MessageToProfessor.txt", "response.sec", aesKey);

        // sign response and save signature
        // get private key from keystore
//        KeyStore keyStore = MyKeyStore.getKeyStore("assignment03_java.ks", "ismase", "pkcs12");
//        PrivateKey myPrivateKey = MyKeyStore.getPrivateKey("assignment03_java", "ismase", keyStore);
//        // get public key from certificate
//        PublicKey myCertificate = Certificate.getPublicKeyFromCertificate("assignment_03.cer");
//        byte[] signature = RSACipher.signFile("response.sec", myPrivateKey);
//        fos = new FileOutputStream(new File("signature.ds"));
//        fos.write(signature);
//        fos.close();
//
//        System.out.printf("The signing and certificate are %s\n",
//                RSACipher.hasValidSignature("response.sec", myCertificate, "signature.ds") ? "OK" : "not OK");
    }
}
