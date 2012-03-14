package mishanesterenko.bpid.des;

import java.io.File;
import java.io.FileInputStream;

/**
 * @author Michael Nesterenko
 *
 */
public class DesConsole {
    /**
     * @param args
     */
    public static void main(final String[] args) {
        try {
            if (args.length != 3) {
                System.out.println("Usage: <crypt|decrypt> <key(8 chars)> <filename>");
                return;
            }
            String key = args[1];
            byte[] keyBytes = key.getBytes("US-ASCII");
            if (DES.isWeak(keyBytes)) {
                System.out.println("Sorry your key is weak.");
            }
            File f = new File(args[2]);
            long fileSize = f.length();
            byte[] fileData = new byte[(int) fileSize];
            int read, off = 0;
            FileInputStream fs = new FileInputStream(f);
            while ((read = fs.read(fileData, off, fileData.length - off)) > 0) {
                off += read;
            }
            if ("crypt".equals(args[0])) {
                DES.crypt(fileData, keyBytes);
            } else {
                DES.decrypt(fileData, keyBytes);
            }
            System.out.write(fileData);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

}
