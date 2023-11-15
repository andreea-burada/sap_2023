package day03.utils;

public class Utils {
    public static String getHexString(byte[] value){
        if (value.length == 0)
            return "byte[] size is zero";
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value){
            result.append(String.format("%02X ", b));
        }
        return result.toString();
    }
}
