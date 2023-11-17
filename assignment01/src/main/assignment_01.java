package main;

public class assignment_01 {
    protected class Utils {
        public static String getHexString(byte[] bytes) {
            if (bytes.length == 0)
                return "byte[] size is zero";
            StringBuilder result = new StringBuilder();
            result.append("0x");
            for (byte b : bytes) {
                result.append(String.format("%02X ", b));
            }
            return result.toString();
        }
    }

    protected class A5_PRNG {
        public static byte[] generatePRNG() {
            return null;
        }
    }

    public static void main(String[] args) {
        // testing grounds
    }
}
