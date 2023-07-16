package net.ladenthin.bitcoinaddressfinder;

import java.math.BigInteger;

public class AddressBytes {

    public static final AddressBytes INVALID_ADDRESS = null;
    public static final int SINGLE_SHA256_BYTE_LEN = 32;
    public static final int DOUBLE_SHA256_BYTE_LEN = 2 * SINGLE_SHA256_BYTE_LEN;
    public static final int PUB_KEY_WITHOUT_PARITY_WITH_DOUBLE_SHA256_BYTE_LEN = PublicKeyBytes.TWO_COORDINATES_NUM_BYTES + DOUBLE_SHA256_BYTE_LEN;
    // TODO store public key with parity in opencl kernel result
    public static final int PUB_KEY_WITH_PARITY_WITH_SHA256_BYTE_LEN = PUB_KEY_WITHOUT_PARITY_WITH_DOUBLE_SHA256_BYTE_LEN + 1;
    private final BigInteger privateKey;
    private final byte[] uncompressed;

    public AddressBytes(BigInteger privateKey, byte[] uncompressed) {
        this.privateKey = privateKey;
        this.uncompressed = uncompressed;
    }

    public byte[] getUncompressed() {
        return uncompressed;
    }
}