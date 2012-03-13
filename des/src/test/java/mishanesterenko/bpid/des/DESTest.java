package mishanesterenko.bpid.des;

import static org.junit.Assert.assertArrayEquals;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

/**
 * @author Michael Nesterenko
 *
 */
public class DESTest {
    @Test
    public void testCrypt() throws UnsupportedEncodingException {
        byte[] data = new byte[] {0, 0, 0, 0, 0, 0, 0, 0};
        byte[] key = {-1, -1, -1, -1, -1, -1, -1, -1};
        byte[] cryptedData = DES.crypt(data, key);
        byte[] decryptedData = DES.decrypt(cryptedData, key);

        assertArrayEquals(data, decryptedData);
    }
}
