package day02;

import java.util.BitSet;
import java.util.HashSet;
import java.util.Set;

public class Test {
    public static void main(String[] args) {
        BitSet bitSet = new BitSet(32);
        bitSet.set(0);  // set to 1 the 1st bit from left to right
        bitSet.set(1, false);   // set to 0 the 2nd bit

        byte seed = (byte) 0b1100_1100;

        for(int i = 0; i < 8; i++) {
            byte mask = (byte) (1 << (7 - i));
            bitSet.set(i, (seed & mask) != 0);
        }

        System.out.println("Bitset: ");
        for(int i = 0; i < bitSet.size(); i++) {
            System.out.print(bitSet.get(i) ? 1 : 0);
            System.out.print(i % 4 == 3 ? " " : "");
        }

        System.out.println();

        // 3 types of collections
        // List - like a dynamic array
        // Set - unique values, ordered
        // Map - like a dictionary with unique keys

        Set<Certificate> certificates = new HashSet<>();

        certificates.add(
                new Certificate("John", "ISM", "RO", "A312B5AD")
        );
        certificates.add(
                new Certificate("John", "ISM", "RO", "A312B5AD")
        );

        for(Certificate certificate : certificates) {
            System.out.println(certificate.toString());
        }


    }
}
