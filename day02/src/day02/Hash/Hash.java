package day02.Hash;

import javax.naming.OperationNotSupportedException;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Hash {
    // 2 steps for message digest:
    //      1. process each block of the input
    //      2. get the final value with digest
    public static byte[] getMessageDigest(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        // use Bouncy Castle
        // MessageDigest md = MessageDigest.getInstance("SHA-1", "BC");

        // compute the hash in one step
        return md.digest(input.getBytes());

        // alternative
//        md.update(input.getBytes());
//        return md.digest();
    }

    public static byte[] getFileMessageDigest(
            String filename,
            String algorithm,
            String provider
            ) throws IOException, OperationNotSupportedException, NoSuchAlgorithmException, NoSuchProviderException {
        File file = new File(filename);
        if(!file.exists()) {
            throw new OperationNotSupportedException("File not found!");
        }
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));

        MessageDigest md = MessageDigest.getInstance(algorithm, provider);

        // watch out for this
        byte[] buffer = new byte[8];
        int noBytesFromFile = 0;

        while((noBytesFromFile = bis.read(buffer)) != -1) {
            md.update(buffer, 0, noBytesFromFile);
        }

        return md.digest();
    }
}
