package mishanesterenko.bpid.des;

import static org.junit.Assert.assertArrayEquals;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

/**
 * @author Michael Nesterenko
 *
 */
public class DESTest {
    @Test
    public void testCryptDecrypt() throws UnsupportedEncodingException {
        Random r = new Random();
        byte[] key = {-1, -1, -1, -1, -1, -1, -1, -1};

        for (int i = 0; i < 10000000; ++i) {
            byte[] srcData = new byte[8 * (r.nextInt(100) + 1)];
            byte[] data = new byte[srcData.length];

            r.nextBytes(srcData); System.arraycopy(srcData, 0, data, 0, srcData.length);
            r.nextBytes(key);

            System.out.print("key: " + Arrays.toString(key) + " src: " + Arrays.toString(srcData));

            DES.crypt(data, key);
            DES.decrypt(data, key);

            try {
                assertArrayEquals(srcData, data);
                System.out.println(" ok!");
            } catch (AssertionError e) {
                System.out.println(" fail!");
                throw e;
            }
        }
    }
}
