package net.ladenthin.bitcoinaddressfinder;

/**
 * Creates {@link AddressBytes} objects from a given result buffer and the respective kernelMode.
 */
public class AddressBytesFactory {

    private byte[] workItemResultBytes;
    private int kernelMode = -1;

    public AddressBytesFactory() {
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
     * @return The created {@link AddressBytes} or <code>null</code> if the result buffer or/and kernelMode are invalid.
     */
    public AddressBytes createAddressBytes() {
        if (parametersAreInvalid()) {
            return null;
        }
        byte[] privateKeyBytes = new byte[AddressBytes.PRIVATE_KEY_NUM_BYTES];
        byte[] addressBytes = new byte[AddressBytes.ADDRESS_NUM_BYTES];

        System.arraycopy(workItemResultBytes, 0, privateKeyBytes, 0, AddressBytes.PRIVATE_KEY_NUM_BYTES);
        System.arraycopy(workItemResultBytes, AddressBytes.PRIVATE_KEY_NUM_BYTES, addressBytes, 0, AddressBytes.ADDRESS_NUM_BYTES);

        return new AddressBytes(privateKeyBytes, addressBytes);
    }

    private boolean parametersAreInvalid() {
        if (workItemResultBytes == null) {
            return true;
        }

        if (kernelMode == OpenCLContext.GEN_ADDRESSES_ONLY_MODE && workItemResultBytes.length == AddressBytes.TOTAL_NUM_BYTES) {
            return false;
        }

        return true;
    }
}