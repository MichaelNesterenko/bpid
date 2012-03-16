package mishanesterenko.bpid.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Random;

/**
 * @author Michael Nesterenko
 *
 */
public class Rsa {
    private final static BigInteger TWO = BigInteger.valueOf(2);

    public final static int PERSIST_RADIX = 10;

    public static BigInteger generateRandomPrime(int bitLength) {
        Random rnd = new Random();
        BigInteger num;
        do {
            num = BigInteger.probablePrime(bitLength, rnd);
        } while (!isPrime(num));
        return num;
    }

    public static boolean isPrime(final BigInteger num) {
        BigInteger cv = TWO.modPow(num.subtract(BigInteger.ONE), num);
        return BigInteger.ONE.equals(cv);
    }

    public static BigInteger generatePublicKey(final BigInteger p, final BigInteger q) {
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger key = p.multiply(q);
        int keyLength = key.bitLength() / 2;
        BigInteger e;
        do {
            e = generateRandomPrime(keyLength == 0 ? 1 : keyLength);
        } while (e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));
        return e;
    }

    public static BigInteger generatePrivateKey(final BigInteger e, final BigInteger p, final BigInteger q) {
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger res = e.modInverse(phi);
        return res;
    }

    private static void mayRsaWork(final byte[] data, final BigInteger n) {
        int bitLength = n.bitLength();
        if ((data.length * 8) % bitLength != 0) {
            throw new IllegalArgumentException("Data size (" + data.length * 8 + ") is not multiple of key length (" + bitLength + " )");
        }
    }

    public static void crypt(final byte[] data, final BigInteger e, final BigInteger n, final OutputStream res) throws IOException {
        mayRsaWork(data, n);

        int blockSize = n.bitLength() / 8 / 2; blockSize = blockSize == 0 ? 1 : blockSize;
        int dataSize = data.length;
        byte[] blockData = new byte[blockSize];
        for (int i = 0; i < dataSize; i += blockSize) {
            System.arraycopy(data, i, blockData, 0, blockSize);
            BigInteger block = new BigInteger(1, blockData);
            block = block.modPow(e, n);
            byte[] cryptedData = toArrayBigInteger(block, n.bitLength());
            res.write(cryptedData);
        }
    }

    private static byte[] toArrayBigInteger(final BigInteger bi, int bitLength) {
        bitLength += bitLength % 8;
        byte[] res = new byte[bitLength / 8];

        for (int i = 0; i < Math.min(bi.bitLength(), bitLength); ++i) {
            res[res.length - 1 - i / 8] |= (bi.testBit(i) ? 1 : 0) << (i % 8);
        }
        return res;
    }

    public static void decrypt(final byte[] data, final BigInteger d, final BigInteger n, final OutputStream res)
            throws IOException {
        mayRsaWork(data, n);

        int decryptBlockSize = n.bitLength() / 8; decryptBlockSize = decryptBlockSize == 0 ? 1 : decryptBlockSize;
        int resBlockSize = n.bitLength() / 2; resBlockSize = resBlockSize == 0 ? n.bitLength() : resBlockSize;
        int dataSize = data.length;
        byte[] blockData = new byte[decryptBlockSize];
        for (int i = 0; i < dataSize; i += decryptBlockSize) {
            System.arraycopy(data, i, blockData, 0, decryptBlockSize);
            BigInteger block = new BigInteger(1, blockData);
            block = block.modPow(d, n);
            byte[] cryptedData = toArrayBigInteger(block, resBlockSize);
            res.write(cryptedData);
        }
    }

    private static void persistKeyPair(final BufferedWriter s, final BigInteger e, final BigInteger n) throws IOException {
        s.write(e.toString(PERSIST_RADIX));
        s.write("\n");
        s.write(n.toString(PERSIST_RADIX));
    }

    public static void persistPublicKey(final BufferedWriter s, final BigInteger e, final BigInteger n) throws IOException {
        persistKeyPair(s, e, n);
    }

    public static void persistPrivateKey(final BufferedWriter s, final BigInteger d, final BigInteger n) throws IOException {
        persistKeyPair(s, d, n);
    }

    private static BigInteger[] loadKeyPair(final BufferedReader br) throws IOException {
        String ed = br.readLine();
        String n = br.readLine();

        BigInteger res[] = new BigInteger[2];
        res[0] = new BigInteger(ed, PERSIST_RADIX);
        res[1] = new BigInteger(n, PERSIST_RADIX);
        return res;
    }

    public static BigInteger[] loadPublicPair(final BufferedReader br) throws IOException {
        return loadKeyPair(br);
    }

    public static BigInteger[] loadPrivatePair(final BufferedReader br) throws IOException {
        return loadKeyPair(br);
    }

    public static BigInteger[] generatePQ(final int keyLength) {
        BigInteger[] res = new BigInteger[2];
        BigInteger p, q;
        do {
          p = Rsa.generateRandomPrime(keyLength / 2);
          q = Rsa.generateRandomPrime(keyLength / 2);
          //System.out.println(p + " " + q + " bl: " + p.multiply(q).bitLength());
      } while (p.multiply(q).bitLength() != keyLength || p.equals(q));
        res[0] = p;
        res[1] = q;
        return res;
    }

}
