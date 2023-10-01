package net.ladenthin.bitcoinaddressfinder;

/**
 * Creates {@link Ripemd160Bytes} objects from a given result buffer and the respective kernelMode.
 */
public class Ripemd160BytesFactory {

    public static final int NUM_BYTES_TOTAL = Ripemd160Bytes.NUM_BYTES_PRIVATE_KEY + Ripemd160Bytes.NUM_BYTES_RIPEMD160;

    private byte[] workItemResultBytes;
    private int kernelMode = -1;

    public Ripemd160BytesFactory() {
        // empty constructor
    }

    /**
     * Set the result buffer containing all raw result values from a single work item.
     *
     * @param workItemResultBytes Byte array containing all raw result values from a single work item.
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
     * Retrieves all raw result values from the result buffer from a single work item.
     *
     * @return The created {@link Ripemd160Bytes} or <code>null</code> if the result buffer or/and kernelMode are invalid.
     */
    public Ripemd160Bytes createRipemd160Bytes() {
        if (parametersAreInvalid()) {
            return null;
        }
        byte[] privateKeyBytes = new byte[Ripemd160Bytes.NUM_BYTES_PRIVATE_KEY];
        byte[] ripemd160Bytes = new byte[Ripemd160Bytes.NUM_BYTES_RIPEMD160];

        System.arraycopy(workItemResultBytes, 0, privateKeyBytes, 0, Ripemd160Bytes.NUM_BYTES_PRIVATE_KEY);
        System.arraycopy(workItemResultBytes, Ripemd160Bytes.NUM_BYTES_PRIVATE_KEY, ripemd160Bytes, 0, Ripemd160Bytes.NUM_BYTES_RIPEMD160);

        return new Ripemd160Bytes(privateKeyBytes, ripemd160Bytes);
    }

    @SuppressWarnings("RedundantIfStatement")
    private boolean parametersAreInvalid() {
        if (workItemResultBytes == null) {
            return true;
        }

        if (kernelMode == OpenCLContext.GEN_RIPEMD160_ONLY_MODE && workItemResultBytes.length == NUM_BYTES_TOTAL) {
            return false;
        }

        return true;
    }
}