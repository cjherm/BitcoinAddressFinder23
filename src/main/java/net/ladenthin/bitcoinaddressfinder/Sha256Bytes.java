package net.ladenthin.bitcoinaddressfinder;

/**
 * Data structure to retrieve and hold SHA256 hash bytes.
 */
public class Sha256Bytes {

    public static final int SHA256_NUM_BITS = 256;
    public static final int ONE_SHA256_NUM_BYTES = (SHA256_NUM_BITS / PublicKeyBytes.BITS_PER_BYTE);

    private final byte[] completeResultBytes;
    private byte[] firstSha256Bytes;
    private byte[] secondSha256Bytes;

    /**
     * @param completeResultBytes Containing the complete result from the OpenCL kernel as byte array.
     */
    public Sha256Bytes(byte[] completeResultBytes) {
        this.completeResultBytes = completeResultBytes;
    }

    /**
     * If not already done, this method will retrieve all bytes representing the first SHA256 hash.
     *
     * @return sha256 hash as byte array
     */
    public byte[] getFirstSha256Bytes() {
        if (firstSha256Bytes == null) {
            firstSha256Bytes = retrieveBytes(PublicKeyBytes.TWO_COORDINATES_NUM_BYTES, OpenCLGridResult.TWO_COORDINATES_NUM_BYTES_SINGLE_SHA256);
        }
        return firstSha256Bytes;
    }

    /**
     * If not already done, this method will retrieve all bytes representing the second SHA256 hash.
     *
     * @return sha256 hash as byte array
     */
    public byte[] getSecondSha256Bytes() {
        if (secondSha256Bytes == null) {
            secondSha256Bytes = retrieveBytes(OpenCLGridResult.TWO_COORDINATES_NUM_BYTES_SINGLE_SHA256, OpenCLGridResult.TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256);
        }
        return secondSha256Bytes;
    }

    private byte[] retrieveBytes(int startReadIndex, int endReadIndex) {
        byte[] array = new byte[endReadIndex - startReadIndex];
        int writeIndex = 0;
        for (int readIndex = startReadIndex; readIndex < endReadIndex; readIndex++) {
            array[writeIndex] = completeResultBytes[readIndex];
            writeIndex++;
        }
        return array;
    }
}