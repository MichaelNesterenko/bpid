package mishanesterenko.bpid.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

/**
 * @author Michael Nesterenko
 *
 */
public class RsaConsole {
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Usage: <generate keylength(32, 64, 128, 256, 512, 1024, 2048, 4096) key files name> <crypt|decrypt> <public/private key file> <filename>");
            return;
        }
        if ("generate".equals(args[0])) {
            int keyLength = Integer.parseInt(args[1]);
            String keyFileName = args[2];

            BigInteger[] pq = Rsa.generatePQ(keyLength);
            BigInteger e = Rsa.generatePublicKey(pq[0], pq[1]);
            BigInteger d = Rsa.generatePrivateKey(e, pq[0], pq[1]);
            BigInteger n = pq[0].multiply(pq[1]);

            BufferedWriter writer = new BufferedWriter(new FileWriter(keyFileName+".pub"));
            try {
                Rsa.persistPublicKey(writer, e, n);
            } finally {
                writer.close();
            }
            writer = new BufferedWriter(new FileWriter(keyFileName));
            try {
                Rsa.persistPrivateKey(writer, d, n);
            } finally {
                writer.close();
            }
            return;
        }
        String fileName = args[1];
        String fileToProcess = args[2];
        BigInteger[] keys;

        if ("crypt".equals(args[0])) {
            keys = Rsa.loadPublicPair(new BufferedReader(new FileReader(fileName)));
        } else {
            keys = Rsa.loadPrivatePair(new BufferedReader(new FileReader(fileName)));
        }
        
        File file = new File(fileToProcess);
        byte[] data = new byte[(int) file.length()];

        int read, off = 0;
        FileInputStream fs = new FileInputStream(fileToProcess);
        while ((read = fs.read(data, off, data.length - off)) > 0) {
            off += read;
        }

        if ("crypt".equals(args[0])) {
            Rsa.crypt(data, keys[0], keys[1], System.out);
        } else {
            Rsa.decrypt(data, keys[0], keys[1], System.out);
        }
    }
}
