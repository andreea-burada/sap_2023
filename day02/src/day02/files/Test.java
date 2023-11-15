package day02.files;

import java.io.*;

public class Test {
    public static void main(String[] args) throws IOException {
        // managing the file system
        File location = new File("C:\\Code Projects\\SAP");
        if(!location.exists()) {
            throw new UnsupportedOperationException("Folder is not there");
        }

        File tempFolder = new File(location.getAbsolutePath() + File.separator + "temp");

        if(!tempFolder.exists()) {
            tempFolder.mkdir();
        } else {
            tempFolder.delete();
        }

        File[] files = location.listFiles();
        for(File file : files) {
            System.out.println(file.getName());
            if (file.isDirectory()) {
                System.out.println(" --- is folder");
            } else {
                System.out.println(" --- is file");
            }
        }

        // text files
        File messageTextFile = new File("message.txt");
        if(!messageTextFile.exists()) {
            messageTextFile.createNewFile();
        }

        PrintWriter printWriter = new PrintWriter(messageTextFile);
        printWriter.println("Hello!");
        printWriter.println("This is a secret message.");

        printWriter.close();

        // reading from text files
        FileReader fileReader = new FileReader(messageTextFile);
        BufferedReader bufferedReader = new BufferedReader(fileReader);

        String line;

        System.out.println("\nReading from text file:");
        while((line = bufferedReader.readLine()) != null) {
            System.out.println(line);
        }
        bufferedReader.close();

        // binary files
        File dataFile = new File("mydata.dat");
        if(!dataFile.exists()) {
            dataFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(dataFile);
        BufferedOutputStream bufFos = new BufferedOutputStream(fos);
        // special class to convert special types to byte array
        DataOutputStream dos = new DataOutputStream(bufFos);

        dos.writeFloat(23.5f);
        dos.writeInt(2);
        dos.writeBoolean(true);
        dos.writeUTF("Stop Joc");
        byte[] values = {0x0A, 0x08};
        dos.writeInt(values.length);
        dos.write(values);

        dos.close();

        // read from a binary file
        FileInputStream fis = new FileInputStream(dataFile);
        BufferedInputStream bis = new BufferedInputStream(fis);
        DataInputStream dis = new DataInputStream(bis);

        float floatVal = dis.readFloat();
        int value = dis.readInt();
        boolean logicVal = dis.readBoolean();
        String stringVal = dis.readUTF();
        int byteArraySize = dis.readInt();
        byte[] byteVal = new byte[byteArraySize];
        dis.read(byteVal, 0, byteArraySize);    // can also use dis.read(byteVal);

        System.out.println("Float value is " + floatVal);
        System.out.println("Integer value is " + value);
        System.out.println("Boolean value is " + logicVal);

        dis.close();

        // binary files with the legacy Random Access File class
        RandomAccessFile raf = new RandomAccessFile(dataFile, "rw");
        values = new byte[] {0x0A, 0x0B, 0x0C};
        for(byte v: values) {
            raf.writeByte(v);
        }

        // move to the beginning of the file
        raf.seek(0);

        byte byteValue = raf.readByte();
        System.out.println("\nFirst byte " + byteValue);
        raf.seek(2);
        byteValue = raf.readByte();
        System.out.println("Last byte " + byteValue);

        raf.close();

    }
}
