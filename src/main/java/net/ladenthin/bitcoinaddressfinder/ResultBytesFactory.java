package net.ladenthin.bitcoinaddressfinder;

/**
 * Creates {@link ResultBytes} objects from a given result buffer and the respective kernelMode.
 */
public class ResultBytesFactory {

    private byte[] workItemResultBytes;
    private int kernelMode = -1;

    public ResultBytesFactory() {
        // empty constructor
    }

    /**
     * Set the result buffer containing all raw result values.
     *
     * @param workItemResultBytes Byte array containing all raw result values.
     */
    public void setResultBufferBytes(byte[] workItemResultBytes) {
        this.workItemResultBytes = workItemResultBytes;
    }

    /**
     * Set the kernelMode which was used to generate the result buffer.
     *
     * @param kernelMode Integer representing the used kernelMode.
     */
    public void setKernelMode(int kernelMode) {
        this.kernelMode = kernelMode;
    }

    /**
     * Retrieves all raw result values from the result buffer and sets all not calculated values to <code>{0, 0, 0,...}</code>.
     *
     * @return The created {@link ResultBytes} or <code>null</code> if the result buffer or/and kernelMode are invalid.
     */
    public ResultBytes createResultBytes() {
        if (parametersAreInvalid()) {
            return null;
        }
        byte[] privateKeyBytes = new byte[ResultBytes.NUM_BYTES_PRIVATE_KEY];
        byte[] publicKeyBytes = new byte[ResultBytes.NUM_BYTES_PUBLIC_KEY];
        byte[] firstSha256Bytes = new byte[ResultBytes.NUM_BYTES_SHA256];
        byte[] ripemd160Bytes = new byte[ResultBytes.NUM_BYTES_RIPEMD160];
        byte[] secondSha256Bytes = new byte[ResultBytes.NUM_BYTES_SHA256];
        byte[] thirdSha256Bytes = new byte[ResultBytes.NUM_BYTES_SHA256];
        byte[] addressBytes = new byte[ResultBytes.NUM_BYTES_ADDRESS];

        if (kernelMode >= OpenCLContext.GEN_BYTEWISE_PUBLIC_KEY_MODE) {
            System.arraycopy(workItemResultBytes, 0, privateKeyBytes, 0, ResultBytes.NUM_BYTES_PRIVATE_KEY);
            System.arraycopy(workItemResultBytes, ResultBytes.NUM_BYTES_PRIVATE_KEY, publicKeyBytes, 0, ResultBytes.NUM_BYTES_PUBLIC_KEY);
        }

        if (kernelMode >= OpenCLContext.GEN_BYTEWISE_1ST_SHA256_MODE) {
            System.arraycopy(workItemResultBytes, ResultBytes.NUM_BYTES_TOTAL_UNTIL_PUBLIC_KEY, firstSha256Bytes, 0, ResultBytes.NUM_BYTES_SHA256);
        }

        if (kernelMode >= OpenCLContext.GEN_BYTEWISE_RIPEMD160_MODE) {
            System.arraycopy(workItemResultBytes, ResultBytes.NUM_BYTES_TOTAL_UNTIL_1ST_SHA256, ripemd160Bytes, 0, ResultBytes.NUM_BYTES_RIPEMD160);
        }

        if (kernelMode >= OpenCLContext.GEN_BYTEWISE_2ND_SHA256_MODE) {
            System.arraycopy(workItemResultBytes, ResultBytes.NUM_BYTES_TOTAL_UNTIL_RIPEMD160, secondSha256Bytes, 0, ResultBytes.NUM_BYTES_SHA256);
        }

        if (kernelMode >= OpenCLContext.GEN_BYTEWISE_3RD_SHA256_MODE) {
            System.arraycopy(workItemResultBytes, ResultBytes.NUM_BYTES_TOTAL_UNTIL_2ND_SHA256, thirdSha256Bytes, 0, ResultBytes.NUM_BYTES_SHA256);
        }

        if (kernelMode == OpenCLContext.GEN_BYTEWISE_ADDRESS_MODE) {
            System.arraycopy(workItemResultBytes, ResultBytes.NUM_BYTES_TOTAL_UNTIL_3RD_SHA256, addressBytes, 0, ResultBytes.NUM_BYTES_ADDRESS);
        }

        return new ResultBytes(privateKeyBytes, publicKeyBytes, firstSha256Bytes, ripemd160Bytes, secondSha256Bytes, thirdSha256Bytes, addressBytes);
    }

    @SuppressWarnings("RedundantIfStatement")
    private boolean parametersAreInvalid() {
        if (workItemResultBytes == null) {
            return true;
        }

        if (kernelMode == OpenCLContext.GEN_BYTEWISE_PUBLIC_KEY_MODE && workItemResultBytes.length >= ResultBytes.NUM_BYTES_TOTAL_UNTIL_PUBLIC_KEY) {
            return false;
        }

        if (kernelMode == OpenCLContext.GEN_BYTEWISE_1ST_SHA256_MODE && workItemResultBytes.length >= ResultBytes.NUM_BYTES_TOTAL_UNTIL_1ST_SHA256) {
            return false;
        }

        if (kernelMode == OpenCLContext.GEN_BYTEWISE_RIPEMD160_MODE && workItemResultBytes.length >= ResultBytes.NUM_BYTES_TOTAL_UNTIL_RIPEMD160) {
            return false;
        }

        if (kernelMode == OpenCLContext.GEN_BYTEWISE_2ND_SHA256_MODE && workItemResultBytes.length >= ResultBytes.NUM_BYTES_TOTAL_UNTIL_2ND_SHA256) {
            return false;
        }

        if (kernelMode == OpenCLContext.GEN_BYTEWISE_3RD_SHA256_MODE && workItemResultBytes.length >= ResultBytes.NUM_BYTES_TOTAL_UNTIL_3RD_SHA256) {
            return false;
        }

        if (kernelMode == OpenCLContext.GEN_BYTEWISE_ADDRESS_MODE && workItemResultBytes.length == ResultBytes.NUM_BYTES_TOTAL_UNTIL_ADDRESS) {
            return false;
        }

        return true;
    }
}