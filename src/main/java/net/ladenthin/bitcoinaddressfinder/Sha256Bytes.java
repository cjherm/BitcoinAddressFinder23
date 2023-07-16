package net.ladenthin.bitcoinaddressfinder;

/**
 * Data structure to retrieve and hold SHA256 hash bytes.
 */
public class Sha256Bytes {

    private final byte[] completeResultBytes;
    private byte[] firstSha256Bytes;

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
            firstSha256Bytes = retrieveBytes(PublicKeyBytes.TWO_COORDINATES_NUM_BYTES, PublicKeyBytes.TWO_COORDINATES_NUM_BYTES_SINGLE_SHA256);
        }
        return firstSha256Bytes;
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