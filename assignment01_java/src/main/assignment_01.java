package main;

import java.util.Arrays;
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

    protected enum LFSR {LFSR_1, LFSR_2, LFSR_3}

    ;

    protected static class A51_LFSR {
        private BitSet bits;
        private static final int LENGTH = 64;
        private static final int[] TAPPED_BITS_01 = {13, 16, 17, 18};
        private static final int[] TAPPED_BITS_02 = {20, 21};
        private static final int[] TAPPED_BITS_03 = {7, 20, 21, 22};

        protected A51_LFSR(
                byte[] seed
        ) {
            if (seed.length * 8 != LENGTH) {
                throw new UnsupportedOperationException("Seed length is incorrect!");
            }
            this.bits = BitSet.valueOf(seed);
        }

        protected byte generatePRNG() {
            boolean[] numberBits = new boolean[8];
            // shift 64 times each register
            int i = 0;
            while (i < 8) {
                // xor the last bits of the three registers
                numberBits[i] = bits.get(18) ^ bits.get(19 + 21) ^ bits.get(19 + 22 + 22);
                shift(LFSR.LFSR_1);
                shift(LFSR.LFSR_2);
                shift(LFSR.LFSR_3);
                i++;
            }

            return bitsToByte(numberBits);
        }

        protected void shift(LFSR lfsrNumber) {
            int i = -1;
            int size = 0;
            boolean xoredBit = false;
            switch (lfsrNumber) {
                case LFSR_1 -> {
                    i = 0;
                    size = 19;
                    xoredBit = bits.get(TAPPED_BITS_01[0]) ^ bits.get(TAPPED_BITS_01[1]) ^ bits.get(TAPPED_BITS_01[2]) ^ bits.get(TAPPED_BITS_01[3]);
                    break;
                }
                case LFSR_2 -> {
                    i = 19;
                    size = 22;
                    xoredBit = bits.get(i + TAPPED_BITS_02[0]) ^ bits.get(i + TAPPED_BITS_02[1]);
                    break;
                }
                case LFSR_3 -> {
                    i = 41;
                    size = 23;
                    xoredBit = bits.get(i + TAPPED_BITS_03[0]) ^ bits.get(i + TAPPED_BITS_03[1]) ^ bits.get(i + TAPPED_BITS_03[2]) ^ bits.get(i + TAPPED_BITS_03[3]);
                    break;
                }
            }

            // shift all bits except the last one to the right
            for (int index = (size + i - 1); index > i; index--) {
                if (bits.get(index - 1)) {
                    bits.set(index);
                } else {
                    bits.clear(index);
                }
            }

            // set bit on position i to xored bit
            if (xoredBit) {
                bits.set(i);
            } else {
                bits.clear(i);
            }
        }

        protected byte bitsToByte(
                boolean[] byteBits
        ) {
            byte result = 0;
            int index = 0;
            // loop through the booleans of the array
            for (boolean bit : byteBits) {
                if (bit) {
                    result |= (byte) (1 << (7 - index));
                }
                index++;
            }
            return result;
        }
    }

    public static class Generator{
        private static byte[] seed;
        private static A51_LFSR generator;
        public static void init(
                byte[] _seed
        ) {
            if (!Arrays.equals(seed, _seed)) {
                generator = new A51_LFSR(_seed);
                seed = _seed;
            }
        }
        public static byte[] generatePRNGs(
                int size
        ) {
            if (generator == null) {
                throw new UnsupportedOperationException("Seed was not initialized!");
            }
            byte[] result = new byte[size];
            for(int i = 0; i < size; i++) {
                result[i] = generator.generatePRNG();
            }
            return result;
        }
    }

    public static void main(String[] args) {
        // testing grounds
        System.out.println(" --- *** --- ");
        String seed = "01:01:01:01:01:01:01:01";
        byte[] seedBytes = HexFormat.ofDelimiter(":").parseHex(seed);

        int noPRNGs = 20;
        System.out.printf("Generating %d numbers...\n", noPRNGs);

        Generator.init(seedBytes);
        byte[] numbers = Generator.generatePRNGs(noPRNGs);

        System.out.printf("Numbers as Hex values: %s\n", Utils.getHexString(numbers));

        System.out.print("Numbers as decimal values: ");
        for (byte number : numbers) {
            System.out.printf("%d ", number);
        }
    }
}
