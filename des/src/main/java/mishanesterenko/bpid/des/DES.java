package mishanesterenko.bpid.des;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

/**
 * @author Michael Nesterenko
 * 
 */
public class DES {
    private static final int BLOCK_SIZE = 64;

    private static final int EFFECTIVE_KEY_SIZE = 56;

    private static final int ROUND_KEY_SIZE = 48;

    private static final int BLOCK_EXTENSION_SIZE = ROUND_KEY_SIZE;

    private static final int CYPHER_TABLE_ROW_COUNT = 8;

    private static final int CYPHER_TABLE_ROW_SIZE = 16;

    private static final int CYPHER_TABLE_BLOCK_SIZE = 4;

    private static final byte[] IP = new byte[] { 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29,
            21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36,
            28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6 };

    private static final byte[] E = new byte[] { 31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0, };

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

    private static final byte[] P = new byte[] {15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24, };

    private static final byte[] C0 = new byte[] {56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, };

    private static final byte[] D0 = new byte[] {62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3, };

    private static final byte[] CYCLIC_SHIFT_COUNT = new byte[] { -1, -1, -2, -2, -2, -2, -2, -2, -1, -2, -2, -2, -2, -2, -2, -1 };

    private static final byte[] ROUND_KEY_PERMUTATION = new byte[] {13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31, };

    private static final byte[] EP = new byte[] {39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24, };

    private static final byte[] DECRYPT_PERMUTATION = new byte[BLOCK_SIZE];

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

        for (int i = 0; i < DECRYPT_PERMUTATION.length / 2; ++i) {
            DECRYPT_PERMUTATION[i] = (byte) (i + DECRYPT_PERMUTATION.length / 2);
            DECRYPT_PERMUTATION[i + DECRYPT_PERMUTATION.length / 2] = (byte) i;
        }
    }

    private static BitSet applyPermutation(final BitSet v, final byte[] perm) {
        BitSet newBitSet = new BitSet(perm.length);
        for (int i = 0; i < perm.length; ++i) {
            newBitSet.set(i, v.get(perm[i]));
        }
        return newBitSet;
    }

    private static BitSet extend(final BitSet v) {
        BitSet extended = new BitSet(BLOCK_EXTENSION_SIZE);
        for (int i = 0; i < BLOCK_EXTENSION_SIZE; ++i) {
            extended.set(i, v.get(E[i]));
        }
        return extended;
    }

    private static BitSet shrink(final BitSet v) {
        BitSet newBitSet = new BitSet(BLOCK_SIZE / 2);

        for (int i = 0; i < 8; ++i) {
            BitSet row = new BitSet(2);
            BitSet col = new BitSet(4);
            BitSet part = new BitSet(6);
            part.or(v.get(i * 6, (i + 1) * 6));

            row.set(0, part.get(0));
            row.set(1, part.get(5));
            col.or(part.get(1, 5));

            int colValue = col.toByteArray().length == 0 ? 0 : col.toByteArray()[0];
            int rowValue = row.toByteArray().length == 0 ? 0 : row.toByteArray()[0];

            {
                BitSet bs = BitSet.valueOf(new byte[] { S[i][rowValue][colValue] });
                for (int j = 0; j < 4; ++j) {
                    newBitSet.set(4 * i + j, bs.get(j));
                }
            }
        }
        return newBitSet;
    }

    private static void cycleShift(final BitSet key, final int shift, final int size) {
        BitSet bs = new BitSet(size);
        for (int i = 0; i < size; ++i) {
            bs.set((i + shift + size) % size, key.get(i));
        }
        key.xor(key);
        key.or(bs);
    }

    private static BitSet f(final BitSet v, final BitSet k) {
        BitSet e = extend(v);
        e.xor(k);
        e = shrink(e);
        e = applyPermutation(e, P);
        return e;
    }

    private static void applyFeistel(final BitSet v, final BitSet key) {
        BitSet bs = new BitSet(BLOCK_SIZE);
        BitSet left = v.get(0, BLOCK_SIZE / 2);
        BitSet right = v.get(BLOCK_SIZE / 2, BLOCK_SIZE);

        copyBits(bs, right, 0, 0, BLOCK_SIZE / 2);
        left.xor(f(right, key));
        copyBits(bs, left, BLOCK_SIZE / 2, 0, BLOCK_SIZE / 2);

        copyBits(v, bs, 0, 0, BLOCK_SIZE);
    }

    private static void copyBits(final BitSet to, final BitSet from, final int dstStartIndex, final int srcStartIndex,
            final int count) {
        for (int i = 0; i < count; ++i) {
            to.set(dstStartIndex + i, from.get(i + srcStartIndex));
        }
    }

    private static void prepareKey(final BitSet key) {
        for (int i = 7; i < 64; i += 8) {
            key.set(i, key.get(i, i + 7).cardinality() % 2 == 0);
        }
    }

    private static void mayDesWork(final byte[] data, byte[] key) {
        if (data.length * 8 % BLOCK_SIZE != 0 || data.length * 8 < BLOCK_SIZE) {
            throw new IllegalArgumentException("Wrong data size");
        }
        if (key.length != 8) {
            throw new IllegalArgumentException("Key size must be 8, not " + key.length);
        }
    }

    private static void fillCacheWithKeys(final List<BitSet> cache, final BitSet c, final BitSet d) {
        BitSet roundKey = new BitSet(ROUND_KEY_SIZE);
        BitSet cCopy = new BitSet(c.size());
        BitSet dCopy = new BitSet(d.size());

        copyBits(cCopy, c, 0, 0, c.size());
        copyBits(dCopy, d, 0, 0, c.size());
        for (int i = 0; i < 16; ++i) {
            cycleShift(c, CYCLIC_SHIFT_COUNT[i], EFFECTIVE_KEY_SIZE / 2);
            cycleShift(d, CYCLIC_SHIFT_COUNT[i], EFFECTIVE_KEY_SIZE / 2);
            copyBits(roundKey, c, 0, 0, c.size());
            copyBits(roundKey, d, BLOCK_SIZE / 2, 0, BLOCK_SIZE / 2);
            roundKey = applyPermutation(roundKey, ROUND_KEY_PERMUTATION);
            cache.add(roundKey);
        }
    }

    /**
     * Crypts arrays of bytes with the specified key.
     * 
     * @param data
     *            size must be multiple of 2 bytes
     * @param key
     *            must be 8 bytes
     * @return
     */
    public static byte[] crypt(final byte[] data, byte[] key) {
        mayDesWork(data, key);

        BitSet keyBits = BitSet.valueOf(key);
        prepareKey(keyBits);
        BitSet c = applyPermutation(keyBits, C0);
        BitSet d = applyPermutation(keyBits, D0);

        BitSet dataBits = BitSet.valueOf(data);
        List<BitSet> cachedKeys = new ArrayList<BitSet>(16);
        fillCacheWithKeys(cachedKeys, c, d);
        for (int i = 0; i < data.length * 8; i += BLOCK_SIZE) {
            BitSet block = dataBits.get(i, i + BLOCK_SIZE);
            block = applyPermutation(block, IP);
            for (int j = 0; j < 16; ++j) {
                applyFeistel(block, cachedKeys.get(j));
                System.out.println(block);
            }
            block = applyPermutation(block, EP);
            System.out.println("EP:" + block);
            copyBits(dataBits, block, i, 0, BLOCK_SIZE);
        }

        return dataBits.toByteArray();
    }

    public static byte[] decrypt(final byte[] data, final byte[] key) {
        mayDesWork(data, key);

        BitSet keyBits = BitSet.valueOf(key);
        prepareKey(keyBits);
        BitSet c = applyPermutation(keyBits, C0);
        BitSet d = applyPermutation(keyBits, D0);

        List<BitSet> cachedKeys = new ArrayList<BitSet>(16);
        fillCacheWithKeys(cachedKeys, c, d);

        BitSet dataBits = BitSet.valueOf(data);
        for (int i = 0; i < dataBits.length(); i += BLOCK_SIZE) {
            BitSet block = dataBits.get(i, i + BLOCK_SIZE);
            block = applyPermutation(block, EP);
            System.out.println("\t" + block);
            block = applyPermutation(block, DECRYPT_PERMUTATION);
            for (int j = 15; j >= 0; --j) {
                applyFeistel(block, cachedKeys.get(j));
                System.out.println("\t" + block);
            }
            block = applyPermutation(block, IP);
            copyBits(dataBits, block, i, 0, BLOCK_SIZE);
        }

        return dataBits.toByteArray();
    }

//    public static void main(String[] args) {
//        byte[] arr = EP;
//        for (int i = 0; i < arr.length; ++i) {
//            System.out.print(arr[i] - 1 + ", ");
//        }
//    }
}
