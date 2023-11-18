package main;

import java.util.BitSet;
import java.util.HexFormat;

public class assignment_01 {
    protected static class Utils {
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

    protected static class LFSR {

    }

    protected static class A5_PRNG {
        private BitSet bits;
        private byte[] seed;
        private static final int LENGTH = 114;
        private static final int SEED_LENGTH = 64;
        private static final int[] CLOCKING_BITS = {8, 10, 10};
        private static final int[] TAPPED_BITS_01 = {13, 16, 17, 18};
        private static final int[] TAPPED_BITS_02 = {20, 21};
        private static final int[] TAPPED_BITS_03 = {7, 20, 21, 22};
        public A5_PRNG(
            byte[] seed
        ) {
            this.bits = new BitSet(LENGTH);
            if (seed.length * 8 != SEED_LENGTH) {
                throw new UnsupportedOperationException("Seed length is incorrect!");
            }
            this.seed = seed;
        }
        public void generatePRNG() {
            BitSet number = (BitSet) this.bits.clone();

        }

        public BitSet getPRNG() {
            return (BitSet) this.bits.clone();
        }
        public void print() {
            System.out.println("\nA5 PRNG BitSet:");
            StringBuilder bitSetBits = new StringBuilder();
            for(int i = 0; i < LENGTH; i++) {
                if (i != 0 && i % 4 == 0) {
                    bitSetBits.append(" ");
                }
                bitSetBits.append(this.bits.get(i) ? 1 : 0);
            }
            System.out.println(bitSetBits);
        }
    }

    public static void main(String[] args) {
        // testing grounds
        System.out.println(" --- *** --- ");
        String seed = "01:01:01:01:01:01:01:01";
        A5_PRNG prng = new A5_PRNG(
                HexFormat.ofDelimiter(":").parseHex(seed)
        );
        prng.print();
        prng.generatePRNG();
        prng.print();
    }
}
