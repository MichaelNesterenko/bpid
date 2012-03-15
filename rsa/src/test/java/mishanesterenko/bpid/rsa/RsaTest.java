package mishanesterenko.bpid.rsa;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Test;

/**
 * @author Michael Nesterenko
 *
 */
public class RsaTest {
    @Test
    public void testPrime() {
        System.out.println(Rsa.generateRandomPrime(1024));
    }

    @Test
    public void testPingaluHinduPower() {
        final int maxIterations = 1000;

        long start = System.currentTimeMillis();
        long dummy = 0;
        for (int i = 2; i <= maxIterations; ++i) {
            for (int j = 1; j <= maxIterations; ++j) {
                //testing simple loops
                dummy++;
            }
        }
        long end = System.currentTimeMillis();
        System.out.println(end - start + " dummy: " + dummy);

        start = System.currentTimeMillis();
        for (int i = 2; i <= maxIterations; ++i) {
            if (i % 100 == 0) {
                end = System.currentTimeMillis();
                System.out.println("Average time per one power is: " + ((double)(start - end)) / 100);
            }
            for (int j = 1; j <= maxIterations; ++j) {
                BigInteger base = BigInteger.valueOf(i);
                BigInteger deg = BigInteger.valueOf(j);
                BigInteger pingalaHindu = Rsa.pingalaHanduPower(base, deg);

                BigInteger plain = BigInteger.valueOf(i);
                BigInteger plainBase = BigInteger.valueOf(i);
                for (int k = 1; k < j; ++k) {
                    plain = plain.multiply(plainBase);
                }

                assertEquals(i + "^" + j, plain, pingalaHindu);
            }
        }
    }
}
