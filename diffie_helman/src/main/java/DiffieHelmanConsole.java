import java.math.BigInteger;
import java.util.Random;

import mishanesterenko.bpid.rsa.Rsa;


/**
 * @author Michael Nesterenko
 *
 */
public class DiffieHelmanConsole {
    public static void main(String[] args) {
        final int keyLength = 16;
        BigInteger p = Rsa.generateRandomPrime(keyLength);
        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger g = BigInteger.ONE;
        boolean found = false;
        do {
            g = g.add(BigInteger.ONE);
            BigInteger l = BigInteger.ONE;
            while (l.compareTo(p1) < 0 && (found = !g.modPow(l, p).equals(BigInteger.ONE))) {
                l = l.add(BigInteger.ONE);
            }
        } while (!found);

        System.out.println("p: " + p);
        System.out.println("g: " + g);

        BigInteger a = new BigInteger(4096, new Random());
        BigInteger b = new BigInteger(4096, new Random());

        System.out.println("a: " + a);
        System.out.println("b: " + b);

        BigInteger A = g.modPow(a, p);
        BigInteger B = g.modPow(b, p);

        System.out.println("A: " + A);
        System.out.println("B: " + B);

        BigInteger Ka = B.modPow(a, p);
        BigInteger Kb = A.modPow(b, p);

        System.out.println("Ka: " + Ka);
        System.out.println("Kb: " + Kb);
        System.out.println("Ka == Kb: " + Ka.equals(Kb));
    }
}
