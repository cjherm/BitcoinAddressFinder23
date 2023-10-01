package net.ladenthin.bitcoinaddressfinder;

import java.util.Arrays;

/**
 * Data structure to store a private key and the RIPEMD-160 hash derived from it.
 */
public class Ripemd160Bytes {

    public static final int NUM_BYTES_PRIVATE_KEY = 32;
    public static final int NUM_BYTES_RIPEMD160 = 20;

    private final byte[] privateKey;
    private final byte[] ripemd160Hash;

    /**
     * Constructor for storing a private key and its RIPEMD-160 hash.
     *
     * @param privateKey    The private key as a byte array
     * @param ripemd160Hash The RIPEMD-160 hash as a byte array
     */
    public Ripemd160Bytes(byte[] privateKey, byte[] ripemd160Hash) {
        this.privateKey = privateKey;
        this.ripemd160Hash = ripemd160Hash;
    }

    /**
     * The private key.
     *
     * @return private key as byte array
     */
    public byte[] getPrivateKey() {
        return privateKey;
    }

    /**
     * The RIPEMD-160 hash.
     *
     * @return RIPEMD-160 hash as byte array
     */
    public byte[] getRipemd160Hash() {
        return ripemd160Hash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Ripemd160Bytes that = (Ripemd160Bytes) o;
        return Arrays.equals(privateKey, that.privateKey) && Arrays.equals(ripemd160Hash, that.ripemd160Hash);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(privateKey);
        result = 31 * result + Arrays.hashCode(ripemd160Hash);
        return result;
    }
}