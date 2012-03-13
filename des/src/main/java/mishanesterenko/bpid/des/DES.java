package mishanesterenko.bpid.des;

import java.util.BitSet;

/**
 * @author Michael Nesterenko
 * 
 */
public class DES {
    private static final int BLOCK_SIZE = 64;

    private static final int BLOCK_EXTENSION_SIZE = 48;

    private static final int CYPHER_TABLE_ROW_COUNT = 8;

    private static final int CYPHER_TABLE_ROW_SIZE = 16;

    private static final int CYPHER_TABLE_BLOCK_SIZE = 4;

    private static final byte[] IP = new byte[] { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30,
            22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37,
            29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

    private static final byte[] E = new byte[] { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

    private static final byte[][][] S = new byte[][][] {
            new byte[][] { new byte[] { 14, 4, 13, 1, 2, 5, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                    new byte[] { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    new byte[] { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    new byte[] { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
            new byte[][] { new byte[] { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    new byte[] { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    new byte[] { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    new byte[] { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }, },
            new byte[][] { new byte[] { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                    new byte[] { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                    new byte[] { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                    new byte[] { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
            new byte[][] { new byte[] { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    new byte[] { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    new byte[] { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    new byte[] { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
            new byte[][] { new byte[] { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    new byte[] { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    new byte[] { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    new byte[] { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
            new byte[][] { new byte[] { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    new byte[] { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    new byte[] { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    new byte[] { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
            new byte[][] { new byte[] { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    new byte[] { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    new byte[] { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    new byte[] { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
            new byte[][] { new byte[] { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    new byte[] { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    new byte[] { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    new byte[] { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }, };

    private static final byte[] P = new byte[] { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27,
            3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

    private static final byte[] C0 = new byte[] { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36 };

    private static final byte[] D0 = new byte[] { 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4 };

    private static final byte[] CYCLIC_SHIFT_COUNT = new byte[] {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    private static final byte[] ROUND_KEY_PERMUTATION = new byte[] {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

    private static final byte[] EP = new byte[] {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

    static {
        assert IP.length == BLOCK_SIZE;
        assert EP.length == BLOCK_SIZE;
        assert E.length == BLOCK_EXTENSION_SIZE;

        assert S.length == CYPHER_TABLE_ROW_COUNT;
        for (byte[][] each : S) {
            assert each.length == CYPHER_TABLE_BLOCK_SIZE;
            for (byte[] eachOfEach : each) {
                assert eachOfEach.length == CYPHER_TABLE_ROW_SIZE;
            }
        }
    }

    private static void applyPermutation(final BitSet v, final byte[] perm) {
        BitSet newBitSet = new BitSet(perm.length);
        for (int i = 0; i < perm.length; ++i) {
            newBitSet.set(i, v.get(perm[i]));
        }
        v.xor(v);
        v.or(newBitSet);
    }

    private static BitSet extend(final BitSet v) {
        if (v.size() != BLOCK_SIZE / 2) {
            throw new IllegalArgumentException("Wrong length: " + v.size());
        }
        BitSet extended = new BitSet(BLOCK_EXTENSION_SIZE);
        for (int i = 0; i < BLOCK_EXTENSION_SIZE; ++i) {
            extended.set(i, v.get(E[i]));
        }
        return extended;
    }

    private static BitSet shrink(final BitSet v) {
        if (v.size() != BLOCK_EXTENSION_SIZE) {
            throw new IllegalArgumentException("Wrong size: " + v.size());
        }
        BitSet newBitSet = new BitSet(BLOCK_SIZE / 2);

        for (int i = 0; i < 8; ++i) {
            BitSet row = new BitSet(2);
            BitSet col = new BitSet(4);
            BitSet part = new BitSet(6);
            part.or(v.get(i * 6, (i + 1) * 6));

            row.set(0, part.get(0)); row.set(1, part.get(5));
            col.or(part.get(1, 5));

            int colValue = col.toByteArray()[0];
            int rowValue = row.toByteArray()[0];

            {
                BitSet bs = BitSet.valueOf(new byte[] {S[i][rowValue][colValue]});
                for (int j = 0; j < 4; ++j) {
                    newBitSet.set(4 * i + j, bs.get(j));
                }
            }
        }
        return newBitSet;
    }

    private void cycleShift(final BitSet key, final int shift) {
        BitSet bs = new BitSet(key.size());
        for (int i = 0; i < key.size(); ++i) {
            bs.set((i + shift) % key.size(), key.get(i));
        }
        key.xor(key);
        key.or(bs);
    }

    private void f(final BitSet v, final BitSet k) {
        BitSet e = extend(v);
        e.xor(k);
        e = shrink(e);
        copyBits(v, e, 0);
    }

    private void applyFeistel(final BitSet v, final BitSet key) {
        if (v.size() != BLOCK_SIZE) {
            throw new IllegalArgumentException("Wrong block size: " + v.size());
        }
        BitSet bs = new BitSet(v.size());
        BitSet left = v.get(0, v.size() / 2);
        BitSet right = v.get(v.size() / 2, v.size());

        copyBits(bs, right, 0);
        

        v.xor(v);
        v.or(bs);
    }

    private void copyBits(final BitSet to, final BitSet from, final int startIndex) {
        for (int i = 0; i < from.size(); ++i) {
            to.set(startIndex + i, from.get(i));
        }
    }

    /**
     * Crypts arrays of bytes with the specified key.
     * @param data size must be multiple of 2 bytes
     * @param key must be 8 bytes
     * @return
     */
    public static byte[] crypt(final byte[] data, byte[] key) {
        if (data.length % 2 != 0) {
            throw new IllegalArgumentException("Wrong data size");
        }
        if (key.length != 8) {
            throw new IllegalArgumentException("Key size must be 8, not " + key.length);
        }

        BitSet keyBits = BitSet.valueOf(key);
        for (int i = 0; i <= 64; i+= 8) {
            keyBits.set(i, keyBits.get(i, i + 7).cardinality() % 2 == 0);
        }

        BitSet dataBits = BitSet.valueOf(data);
        for (int i = 0; i < dataBits.length(); i += BLOCK_SIZE) {
            BitSet block = dataBits.get(i, i + BLOCK_SIZE);
            applyPermutation(block, IP);
            
        }
        
        return null;
    }
}
