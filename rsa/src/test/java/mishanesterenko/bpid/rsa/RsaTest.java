package mishanesterenko.bpid.rsa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

import org.junit.Ignore;
import org.junit.Test;

/**
 * @author Michael Nesterenko
 *
 */
public class RsaTest {
    @Test @Ignore
    public void testIsPrime() {
        BigInteger num = new BigInteger("127108435736657059435269177623415244157933295178004463647952130224955945070962826236530834080865939342537515852129288392436922163509707156507151966268454895629991545164838864260139856947329238003048672417162072429488042283379281437514670693419290392197529869131163708486564371678503364652796819439743454964233");
        assertTrue(Rsa.isPrime(num));
    }

    @Test @Ignore
    public void testPrimeGeneration() {
        final int keyLength= 1024;
        BigInteger prime = Rsa.generateRandomPrime(keyLength);
        assertEquals(keyLength, prime.bitLength());
        System.out.println(prime);
    }

    @Test @Ignore
    public void testGeneratePublicKey() {
        final int keyLength = 8;
        BigInteger p = Rsa.generateRandomPrime(keyLength / 2);
        BigInteger q = Rsa.generateRandomPrime(keyLength / 2);
        System.out.println(Rsa.generatePublicKey(p, q));
    }

    @Test @Ignore
    public void testGeneratePrivateKey() {
        BigInteger p = Rsa.generateRandomPrime(1024);
        BigInteger q = Rsa.generateRandomPrime(1024);
        BigInteger e = Rsa.generatePublicKey(p, q);
        BigInteger d = Rsa.generatePrivateKey(e, p, q);
        System.out.println(d);
    }

    @Test //@Ignore
    public void testKeyPersist() throws IOException {
        final int keyLength = 1024;
        BigInteger pq[] = Rsa.generatePQ(keyLength / 2);
        BigInteger p = pq[0], q = pq[1];
//        do {
//            p = Rsa.generateRandomPrime(keyLength / 2);
//            q = Rsa.generateRandomPrime(keyLength / 2);
//            System.out.println(p + " " + q + " bl: " + p.multiply(q).bitLength());
//        } while (p.multiply(q).bitLength() != keyLength || p.equals(q));
        BigInteger e = Rsa.generatePublicKey(p, q);
        BigInteger d = Rsa.generatePrivateKey(e, p, q);
        BigInteger n = p.multiply(q);

        BufferedWriter fw = new BufferedWriter(new FileWriter("key.pub"));
        Rsa.persistPublicKey(fw, e, n);
        fw.close();
        fw = new BufferedWriter(new FileWriter("key"));
        Rsa.persistPrivateKey(fw, d, n);
        fw.close();

        BigInteger[] keys = Rsa.loadPublicPair(new BufferedReader(new FileReader("key.pub")));
        BigInteger eLoaded = keys[0];
        BigInteger publicN = keys[1];

        keys = Rsa.loadPrivatePair(new BufferedReader(new FileReader("key")));
        BigInteger dLoaded = keys[0];
        BigInteger privateN = keys[1];

        assertEquals("Modulos should be equal", publicN, privateN);
        assertEquals("Public key parts should be equal", e, eLoaded);
        assertEquals("Private key parts should be equal", d, dLoaded);
    }

    @Test
    public void testRsa() throws FileNotFoundException, IOException {
        final int keyLength = 1024;
        byte[] srcData = new byte[2 * keyLength / 8];
        byte[] data = new byte[srcData.length];

        new Random(0).nextBytes(srcData);
        System.arraycopy(srcData, 0, data, 0, data.length);

        BigInteger[] keys = Rsa.loadPublicPair(new BufferedReader(new FileReader("key.pub")));
        BigInteger e = keys[0];
        BigInteger publicN = keys[1];

        keys = Rsa.loadPrivatePair(new BufferedReader(new FileReader("key")));
        BigInteger d = keys[0];
        BigInteger privateN = keys[1];

        assertTrue("Modulos should be equal", publicN.equals(privateN));

        ByteArrayOutputStream res = new ByteArrayOutputStream();
        Rsa.crypt(data, e, publicN, res);
        data = res.toByteArray();
        res = new ByteArrayOutputStream();
        Rsa.decrypt(data, d, publicN, res);
        data = res.toByteArray();

        assertArrayEquals(srcData, data);
    }
}
