package day04.AsymmetricKeys;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class Test {
    public static void main(String[] args) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        // testing grounds
        KeyStore keyStore = KeyStoreManager.getKeyStore("keys/ismkeystore.ks", "passks", "pkcs12");
        KeyStoreManager.list(keyStore);

        PublicKey publicKey = KeyStoreManager.getPublicKey("ismkey1", keyStore);
        PrivateKey privateKey = KeyStoreManager.getPrivateKey("ismkey1", "passks", keyStore);

        System.out.println("Public Key:");
        System.out.println(Utils.getHexString(publicKey.getEncoded()));

        System.out.println();

        System.out.println("Private Key:");
        System.out.println(Utils.getHexString(privateKey.getEncoded()));

        System.out.println();

        PublicKey publicKeyCertificate = PublicCertificate.getCertificateKey("keys/ISMCertificateX509.cer");

        System.out.println("Public Key from Certificate:");
        System.out.println(Utils.getHexString(publicKeyCertificate.getEncoded()));
    }
}
