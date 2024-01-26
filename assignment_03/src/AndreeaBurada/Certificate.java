package AndreeaBurada;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class Certificate {
    public static PublicKey getPublicKeyFromCertificate(
            String certificateFileName
    ) throws IOException, CertificateException {
        File certificateFile = new File(certificateFileName);
        FileInputStream fis = new FileInputStream(certificateFile);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate certificate = factory.generateCertificate(fis);
        fis.close();
        return certificate.getPublicKey();
    }
}
