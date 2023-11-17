package day04.AsymmetricKeys;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class KeyStoreManager {
    public static KeyStore getKeyStore(
            String keyStoreFile,
            String keyStorePass,
            String keyStoreType
    ) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        File file = new File(keyStoreFile);
        if (!file.exists()) {
            throw new UnsupportedOperationException("KeyStore file does not exist.");
        }

        FileInputStream fis = new FileInputStream(file);

        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(fis, keyStorePass.toCharArray());

        fis.close();

        return keyStore;
    }

    public static void list(
            KeyStore keyStore
    ) throws KeyStoreException {
        System.out.println("\nKeyStore content:");
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.printf("\tEntry: %s", alias);
            if (keyStore.isCertificateEntry(alias)) {
                System.out.print("\t-- is a certificate");
            }
            if (keyStore.isKeyEntry(alias)) {
                System.out.print("\t-- is a key pair");
            }
            System.out.println();
        }
    }

    public static PublicKey getPublicKey(
            String alias,
            KeyStore keyStore
    ) throws KeyStoreException {
        if (keyStore == null) {
            throw new UnsupportedOperationException("Missing Key Store");
        }
        if (keyStore.containsAlias(alias)) {
            // certificate = public key
            return keyStore.getCertificate(alias).getPublicKey();
        }
        return null;
    }

    public static PrivateKey getPrivateKey(
            String alias,
            String password,
            KeyStore keyStore
    ) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        if (keyStore == null) {
            throw new UnsupportedOperationException("Missing Key Store");
        }
        if (keyStore.containsAlias(alias)) {
            // certificate = public key
            return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        }
        return null;
    }
}
