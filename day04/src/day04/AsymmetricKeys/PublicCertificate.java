package day04.AsymmetricKeys;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PublicCertificate {
    public static PublicKey getCertificateKey(
            String certificateFile
    ) {
        try (FileInputStream fis = new FileInputStream(new File(certificateFile))) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fis);
            fis.close();
            return certificate.getPublicKey();
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException ex) {
            throw new UnsupportedOperationException("!!! File not found !!!");
        }
    }
}
