package net.ladenthin.bitcoinaddressfinder;

import java.util.Arrays;

/**
 * Data structure to store a private key and the address derived from it.
 */
public class AddressBytes {

    public static final AddressBytes INVALID_ADDRESS = null;
    public static final int SINGLE_SHA256_BYTE_LEN = 32;
    public static final int DOUBLE_SHA256_BYTE_LEN = 2 * SINGLE_SHA256_BYTE_LEN;
    public static final int PUB_KEY_WITHOUT_PARITY_WITH_DOUBLE_SHA256_BYTE_LEN = PublicKeyBytes.TWO_COORDINATES_NUM_BYTES + DOUBLE_SHA256_BYTE_LEN;
    public static final int PRIVATE_KEY_NUM_BYTES = 32;
    public static final int ADDRESS_NUM_BYTES = 25;
    public static final int TOTAL_NUM_BYTES = PRIVATE_KEY_NUM_BYTES + ADDRESS_NUM_BYTES;

    private final byte[] privateKey;
    private final byte[] address;

    /**
     * Constructor for storing a private key and its address.
     *
     * @param privateKey The private key as a byte array
     * @param address    The address as a byte array
     */
    public AddressBytes(byte[] privateKey, byte[] address) {
        this.privateKey = privateKey;
        this.address = address;
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
     * The address.
     *
     * @return address as byte array
     */
    public byte[] getAddress() {
        return address;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AddressBytes that = (AddressBytes) o;
        return Arrays.equals(privateKey, that.privateKey) && Arrays.equals(address, that.address);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(privateKey);
        result = 31 * result + Arrays.hashCode(address);
        return result;
    }
}