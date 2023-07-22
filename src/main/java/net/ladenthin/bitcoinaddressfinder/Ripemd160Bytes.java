package net.ladenthin.bitcoinaddressfinder;

/**
 * Data structure to retrieve and hold SHA-256 hash bytes and RIPEMD-160 together.
 */
public class Ripemd160Bytes {

    public static final int RIPEMD160_LENGTH_IN_BYTES = 20;
    public static final int RESULT_LENGTH_IN_BYTES = OpenCLGridResult.TWO_COORDINATES_NUM_BYTES_SINGLE_SHA256 + RIPEMD160_LENGTH_IN_BYTES;
    private final byte[] sha256Hash;
    private final byte[] ripemd160Hash;

    /**
     * @param sha256Hash The SHA-256 hash as a byte array
     * @param ripemd160Hash The RIPEMD-160 hash as a byte array
     */
    public Ripemd160Bytes(byte[] sha256Hash, byte[] ripemd160Hash) {
        this.sha256Hash = sha256Hash;
        this.ripemd160Hash = ripemd160Hash;
    }

    /**
     * The SHA-256 hash of a uncompressed public key.
     *
     * @return SHA-256 hash as byte array
     */
    public byte[] getSha256Bytes() {
        return sha256Hash;
    }

    /**
     * The RIPEMD-160 hash of the SHA-256 hash.
     *
     * @return RIPEMD-160 hash as byte array
     */
    public byte[] getRipemd160Bytes() {
        return ripemd160Hash;
    }
}