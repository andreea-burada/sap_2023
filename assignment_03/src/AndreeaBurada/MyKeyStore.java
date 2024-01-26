package AndreeaBurada;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class MyKeyStore {
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

        KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load(fis, keyStorePass.toCharArray());

        fis.close();
        return ks;
    }

    public static PrivateKey getPrivateKey(
            String alias,
            String keyPass,
            KeyStore ks
    ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        if(ks == null) {
            throw new UnsupportedOperationException("Missing Key Store");
        }
        if(ks.containsAlias(alias)) {
            return (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        } else {
            return null;
        }
    }
}
