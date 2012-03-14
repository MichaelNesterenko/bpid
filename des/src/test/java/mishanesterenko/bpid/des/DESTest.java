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
        byte[] srcData = new byte[] {0, 1, 0, 0, 0, 0, 0, 0};
        byte[] data = new byte[srcData.length]; System.arraycopy(srcData, 0, data, 0, srcData.length);
        byte[] key = {-1, -1, -1, -1, -1, -1, -1, -1};
        DES.crypt(data, key);
        DES.decrypt(data, key);

        assertArrayEquals(srcData, data);
    }
}
