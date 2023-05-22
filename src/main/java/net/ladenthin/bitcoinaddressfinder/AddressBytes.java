package net.ladenthin.bitcoinaddressfinder;

import java.math.BigInteger;

public class AddressBytes {

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