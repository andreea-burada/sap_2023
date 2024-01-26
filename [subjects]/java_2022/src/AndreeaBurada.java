import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.synth.SynthSeparatorUI;

public class AndreeaBurada {

    // provided method for getting the public key from a X509 certificate file
    public static PublicKey getCertificateKey(String file) throws FileNotFoundException, CertificateException {
        FileInputStream fis = new FileInputStream(file);

        CertificateFactory factory = CertificateFactory.getInstance("X509");

        X509Certificate certificate = (X509Certificate) factory.generateCertificate(fis);

        return certificate.getPublicKey();
    }

    //provided method to print a byte array to console
    public static String getHex(byte[] array) {
        StringBuilder output = new StringBuilder();
        for(byte value : array) {
            output.append(String.format("%02X ", value));
        }
        return output.toString();
    }


    // method for getting the private key from a keystore
    public static PrivateKey getPrivateKey(
            String keyStoreFileName,
            String keyStorePass,
            String keyAlias,
            String keyPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException {
        KeyStore keyStore = getKeyStore(keyStoreFileName, keyStorePass, "pkcs12");
        if(keyStore.containsAlias(keyAlias)) {
            return (PrivateKey) keyStore.getKey(keyAlias, keyPass.toCharArray());
        } else {
            return null;
        }
    }

    public static KeyStore getKeyStore(
            String keyStoreFile,
            String keyStorePass,
            String keyStoreType
    ) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        File file = new File(keyStoreFile);
        if(!file.exists()) {
            throw new UnsupportedOperationException("Missing key store file");
        }

        FileInputStream fis = new FileInputStream(file);

        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(fis, keyStorePass.toCharArray());

        fis.close();
        return keyStore;
    }


    // method for computing the RSA digital signature
    public static void getDigitalSignature(
            String inputFileName,
            String signatureFileName,
            PrivateKey key)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {

        //generate and store the RSA digital signature of the inputFileName file
        //store it in signatureFileName file
        byte[] signature = signFile(inputFileName, key);
        File signatureFile = new File(signatureFileName);
        if (!signatureFile.exists()) {
            signatureFile.createNewFile();
        }
        try (FileOutputStream outputStream = new FileOutputStream(signatureFile)) {
            outputStream.write(signature);
        }
    }

    public static byte[] signFile(String filename, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        File file = new File(filename);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(file);

        byte[] fileContent = fis.readAllBytes();

        fis.close();

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);

        signature.update(fileContent);
        return signature.sign();
    }


    //proposed function for generating the hash value
    public static byte[] getSHA1Hash(File file)
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException {

        //generate the SHA-1 value of the received file
        FileInputStream passwordStream = new FileInputStream(file);
        String password = new String(passwordStream.readAllBytes());
        if (password.length() == 0) {
            throw new RuntimeException("Invalid password!");
        }
        MessageDigest md = MessageDigest.getInstance("SHA1");
        return md.digest(password.getBytes());
    }

    //proposed function for decryption
    public static void decryptAESCBC(
            File inputFile,
            File outputFile,
            byte[] key)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException, BadPaddingException,
            IOException {

        //decrypt the input file using AES in CBC
        //the file was encrypted without using padding - didn't need it
        //the IV is at the beginning of the input file
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        if(!outputFile.exists()) {
            outputFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);

        // no padding
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        //getting the IV from the file
        byte[] IV = new byte[cipher.getBlockSize()];
        fis.read(IV);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

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
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }

    //proposed function for print the text file content
    public static void printTextFileContent(
            String textFileName) throws	IOException {

        //print the text file content on the console
        //you need to do this to get values for the next request
//        System.out.println("You must load the OriginalData.txt file and print its content");
        try (BufferedReader br = new BufferedReader(new FileReader(textFileName))) {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            System.out.println(sb.toString());
        }
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

        Signature signatureModule = Signature.getInstance("SHA256withRSA");
        signatureModule.initVerify(key);

        signatureModule.update(fileContent);
        return signatureModule.verify(signature);
    }

    public static void main(String[] args) {
        try {


            /*
             *
             * @author - Please write your name here and also rename the class
             *
             *
             *
             */
            /*
             * Request 1
             */
            File passFile = new File("Passphrase.txt");
            byte[] hashValue = getSHA1Hash(passFile);
            System.out.println("SHA1: " + getHex(hashValue));


            //check point - you should get 268F10........


            /*
             * Request 2
             */

            //generate the key form previous hash
            byte[] key = Arrays.copyOf(hashValue, 128 / 8);

            //decrypt the input file
            //there is no need for padding and the IV is written at the beginning of the file
            decryptAESCBC(new File("EncryptedData.data"), new File("OriginalData.txt"), key);


            printTextFileContent("OriginalData.txt");

            //get the keyStorePassword from OriginalMessage.txt. Copy paste the values from the console
            String ksPassword = "you_already_made_it";
            String keyName = "sapexamkey";
            String keyPassword = "grant_access";

            /*
             * Request 3
             */


            //compute the RSA digital signature for the EncryptedMessage.cipher file and store it in the
            //	signature.ds file

            PrivateKey privKey = getPrivateKey("sap_exam_keystore.ks",ksPassword,keyName,keyPassword);
            getDigitalSignature("OriginalData.txt", "DataSignature.ds", privKey);


            //optionally - you can check if the signature is ok using the given SAPExamCertificate.cer
            //not mandatory
            //write code that checks the previous signature
            PublicKey certificatePublicKey = getCertificateKey("SAPExamCertificate.cer");
            if(hasValidSignature("OriginalData.txt", certificatePublicKey, "DataSignature.ds"))
            {
                System.out.println("File is the original one");
            } else {
                System.out.println("File has been changed");
            }

            System.out.println("Done");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
