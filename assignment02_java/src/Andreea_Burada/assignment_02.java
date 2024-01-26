package Andreea_Burada;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

public class assignment_02 {
    public static byte[] fromStringToBytes(String input) {
        // Java 17+
        return HexFormat.of().parseHex(input);

        // older versions of Java
//        int len = input.length();
//        byte[] data = new byte[len / 2];
//        for (int i = 0; i < len; i += 2) {
//            data[i / 2] = (byte) ((Character.digit(input.charAt(i), 16) << 4)
//                    + Character.digit(input.charAt(i+1), 16));
//        }

//        return data;
    }

    public static String fromBytesToString(byte[] input) {
        return new String(input);
    }

    public static byte[] getHash(byte[] input, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(input);
    }

    public static boolean checkPassword(byte[] password, byte[] allegedPassword) {
        for (int i = 0; i < password.length; i++) {
            if (password[i] != allegedPassword[i])
                return false;
        }
        return true;
    }

    public static void main(String[] args) {
        // open file
        File passwordList = new File("ignis-10M.txt");

        try (InputStream fileInputStream = new BufferedInputStream(new FileInputStream(passwordList))) {
            final String passwordHash = "b0ccd2cf36952dbe2b0d5848ba3920fcc796001ed4702f78e6fb08b9c88f00f5";
            final byte[] passwordHashBytes = fromStringToBytes(passwordHash);

            byte[] currentPassword = new byte[128];
            currentPassword[0] = 'i';
            currentPassword[1] = 's';
            currentPassword[2] = 'm';
            currentPassword[3] = 's';
            currentPassword[4] = 'a';
            currentPassword[5] = 'p';

            byte[] toHash;
            byte byteBuffer;
            byte[] md5;
            byte[] sha256;

            int index = 6;

            long tStart = System.currentTimeMillis();
            long tFinal;

            while ((byteBuffer = (byte) fileInputStream.read()) != -1) {
                if (byteBuffer == '\n') {
                    toHash = Arrays.copyOf(currentPassword, index);
                    md5 = getHash(toHash, "MD5");
                    sha256 = getHash(md5, "SHA-256");
                    if (checkPassword(passwordHashBytes, sha256)) {
                        tFinal = System.currentTimeMillis();
                        System.out.printf("Found password = %s; Duration is: %d\n",
                                fromBytesToString(toHash).split("ismsap")[1], tFinal - tStart);
                        break;
                    }
                    index = 6;
                } else {
                    currentPassword[index++] = byteBuffer;
                }
            }
            System.out.println("Done...");
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}
