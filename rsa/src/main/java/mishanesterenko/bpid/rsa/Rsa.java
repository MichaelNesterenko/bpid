package mishanesterenko.bpid.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
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
        BigInteger cv = pingalaHanduPowerMod(TWO, num.add(BigInteger.ONE.negate()), num);

        return BigInteger.ONE.equals(cv);
    }

    public static BigInteger pingalaHanduPowerMod(final BigInteger base, final BigInteger deg, final BigInteger mod) {
        BigInteger cv = base;
        for (int i = deg.bitLength() - 2; i >= 0; --i) {
            boolean op = deg.testBit(i);
            cv = cv.multiply(cv);
            cv = mod != null ? cv.mod(mod) : cv;
            cv = op ? (mod != null ? cv.multiply(base).mod(mod) : cv.multiply(base)) : cv;
        }

        return cv;
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
        for (long k = 1; k < Long.MAX_VALUE; ++k) {
            BigInteger up = BigInteger.ONE.add(BigInteger.valueOf(1).multiply(phi));
            BigInteger rem = up.mod(e);
            if (rem.equals(BigInteger.ZERO)) {
                return up.divide(e);
            }
        }
        throw new IllegalStateException("Can not create private key.");
    }

    private static void mayRsaWork(final byte[] data, final BigInteger n) {
        int bitLength = n.bitLength();
        if ((data.length * 8) % ((bitLength / 8) * 8) != 0) {
            throw new IllegalArgumentException("Data size (" + data.length * 8 + ") is not multiple of key length (" + bitLength + " )");
        }
    }

    public static void crypt(final byte[] data, final BigInteger e, final BigInteger n) {
        mayRsaWork(data, n);

        int blockSize = n.bitLength() / 8;
        int dataSize = data.length;
        byte[] blockData = new byte[blockSize];
        for (int i = 0; i < dataSize; i += blockSize) {
            System.arraycopy(data, i, blockData, 0, blockSize);
            BigInteger block = new BigInteger(1, blockData);
            block = pingalaHanduPowerMod(block, e, n);
            byte[] cryptedData = block.toByteArray();
            System.arraycopy(cryptedData, 0, data, i, blockSize);
        }
    }

    public static void decrypt(final byte[] data, final BigInteger d, final BigInteger n) {
        mayRsaWork(data, n);
        crypt(data, d, n);
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

}
