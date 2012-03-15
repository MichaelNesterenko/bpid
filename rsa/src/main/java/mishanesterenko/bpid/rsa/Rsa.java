package mishanesterenko.bpid.rsa;

import java.math.BigInteger;

/**
 * @author Michael Nesterenko
 *
 */
public class Rsa {
    public static BigInteger generateRandomPrime(int bitLength) {
        return new BigInteger("0");
    }

    public static BigInteger pingalaHanduPower(final BigInteger base, final BigInteger deg) {
        BigInteger cv = base;
        for (int i = deg.bitLength() - 2; i >= 0; --i) {
            boolean op = deg.testBit(i);
            cv = op ? cv.multiply(cv).multiply(base) : cv.multiply(cv);
        }

        return cv;
    }
}
