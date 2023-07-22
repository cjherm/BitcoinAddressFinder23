package net.ladenthin.bitcoinaddressfinder;

/**
 * Data structure to retrieve and hold SHA256 hash bytes together with the uncompressed public key with parity.
 */
public class Sha256Bytes {

    public static final int SHA256_NUM_BITS = 256;
    public static final int ONE_SHA256_NUM_BYTES = (SHA256_NUM_BITS / PublicKeyBytes.BITS_PER_BYTE);

    private final byte[] publicKeyUncompressed;
    private final byte[] firstSha256Bytes;
    private final byte[] secondSha256Bytes;

    /**
     * @param publicKeyUncompressed The uncompressed public key with parity to be hashed with SHA256
     * @param firstSha256Bytes The SHA256 hash of the uncompressed public key with parity
     * @param secondSha256Bytes The SHA256 hash of previous SHA256 hash
     */
    public Sha256Bytes(byte[] publicKeyUncompressed, byte[] firstSha256Bytes, byte[] secondSha256Bytes) {
        this.publicKeyUncompressed = publicKeyUncompressed;
        this.firstSha256Bytes = firstSha256Bytes;
        this.secondSha256Bytes = secondSha256Bytes;
    }

    /**
     * The uncompressed public key with parity.
     *
     * @return uncompressed public key as byte array
     */
    public byte[] getPublicKeyUncompressed() {
        return publicKeyUncompressed;
    }

    /**
     * The SHA256 hash of the uncompressed public key.
     *
     * @return first SHA256 hash as byte array
     */
    public byte[] getFirstSha256Bytes() {
        return firstSha256Bytes;
    }

    /**
     * The SHA256 hash of the previous Sha256 hash.
     *
     * @return second SHA256 hash as byte array
     */
    public byte[] getSecondSha256Bytes() {
        return secondSha256Bytes;
    }
}