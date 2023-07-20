// @formatter:off
/*
 * Copyright 2020 Bernard Ladenthin bernard.ladenthin@gmail.com
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// @formatter:on
package net.ladenthin.bitcoinaddressfinder;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class OpenCLGridResult {

    public static final int TWO_COORDINATES_NUM_BYTES_SINGLE_SHA256 = PublicKeyBytes.TWO_COORDINATES_NUM_BYTES + Sha256Bytes.ONE_SHA256_NUM_BYTES;
    public static final int TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256 = TWO_COORDINATES_NUM_BYTES_SINGLE_SHA256 + Sha256Bytes.ONE_SHA256_NUM_BYTES;

    private final ByteBufferUtility byteBufferUtility = new ByteBufferUtility(true);
    private final BigInteger[] secretKeys;
    private final int workSize;
    private final boolean chunkMode;
    private final int kernelMode;
    private ByteBuffer result;

    OpenCLGridResult(BigInteger[] secretKeys, int workSize, ByteBuffer result, boolean chunkMode, int kernelMode)
            throws InvalidWorkSizeException {
        checkPrivateKeysAndWorkSize(secretKeys, workSize, chunkMode);
        this.secretKeys = secretKeys;
        this.workSize = workSize;
        this.result = result;
        this.chunkMode = chunkMode;
        this.kernelMode = kernelMode;
    }

    private void checkPrivateKeysAndWorkSize(BigInteger[] secretKeys, int workSize, boolean chunkMode)
            throws InvalidWorkSizeException {
        if (!chunkMode && (secretKeys.length != workSize)) {
            throw new InvalidWorkSizeException(
                    "When CHUNKMODE is DEACTIVATED, the number of the secretKeys (=" + secretKeys.length + ") must be EQUAL to the workSize (=" + workSize + ")!");
        } else if (chunkMode && secretKeys.length > 1) {
            // TODO use a logger
            System.out.println("Too many secret keys (=" + secretKeys.length + ") when CHUNKMODE is ACTIVATED! Will use first secret key ONLY!");
        }
    }

    public ByteBuffer getResult() {
        return result;
    }

    /**
     * Frees byte buffer and sets result to NULL
     */
    public void freeResult() {
        byteBufferUtility.freeByteBuffer(result);
        result = null;
    }

    /**
     * @return the calculated public keys
     */
    public PublicKeyBytes[] getPublicKeyBytes() {
        PublicKeyBytes[] publicKeys = new PublicKeyBytes[workSize];
        for (int i = 0; i < workSize; i++) {
            PublicKeyBytes publicKeyBytes;
            if (chunkMode) {
                publicKeyBytes = getPublicKeyFromByteBufferXY(result, i, secretKeys[0]);
                publicKeys[i] = publicKeyBytes;
            } else {
                publicKeyBytes = getPublicKeyFromByteBufferXY(result, i, secretKeys[workSize - 1 - i]);
                publicKeys[workSize - 1 - i] = publicKeyBytes;
            }

        }
        return publicKeys;
    }

    /**
     * Generated with ChatGPT
     * Prompt: "i need a java method which will revert the order in a byte array"
     *
     * @param array to be reverted
     * @return reverted array
     */
    public static byte[] reverseByteArray(byte[] array) {
        byte[] reversedArray = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            reversedArray[i] = array[array.length - 1 - i];
        }
        return reversedArray;
    }

    /**
     * Read the inner bytes in reverse order.
     */
    private PublicKeyBytes getPublicKeyFromByteBufferXY(ByteBuffer b, int keyNumber,
                                                        BigInteger secretKeyBase) {

        BigInteger secret = AbstractProducer.calculateSecretKey(secretKeyBase, keyNumber);

        if (BigInteger.ZERO.equals(secret)) {
            return PublicKeyBytes.INVALID_KEY_ONE;
        }

        byte[] uncompressed = new byte[PublicKeyBytes.PUBLIC_KEY_UNCOMPRESSED_BYTES];
        uncompressed[0] = PublicKeyBytes.PARITY_UNCOMPRESSED;

        // Same way as in OpenCL kernel:
        // int r_offset = PUBLIC_KEY_LENGTH_X_Y_WITHOUT_PARITY * global_id;
        int keyOffsetInByteBuffer;
        if (kernelMode == OpenCLContext.GEN_PUBLIC_KEYS_MODE) {
            keyOffsetInByteBuffer = PublicKeyBytes.TWO_COORDINATES_NUM_BYTES * keyNumber;
        } else if (kernelMode == OpenCLContext.GEN_SHA256_MODE) {
            keyOffsetInByteBuffer = TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256 * keyNumber;
        } else {
            // TODO handle else case
            return null;
        }

        // read ByteBuffer
        byte[] yx = new byte[PublicKeyBytes.TWO_COORDINATES_NUM_BYTES];
        for (int i = 0; i < PublicKeyBytes.TWO_COORDINATES_NUM_BYTES; i++) {
            yx[yx.length - 1 - i] = b.get(keyOffsetInByteBuffer + i);
        }

        // copy x
        System.arraycopy(yx, PublicKeyBytes.ONE_COORDINATE_NUM_BYTES, uncompressed, PublicKeyBytes.PARITY_BYTES_LENGTH,
                PublicKeyBytes.ONE_COORDINATE_NUM_BYTES);
        // copy y
        System.arraycopy(yx, 0, uncompressed,
                PublicKeyBytes.PARITY_BYTES_LENGTH + PublicKeyBytes.ONE_COORDINATE_NUM_BYTES,
                PublicKeyBytes.ONE_COORDINATE_NUM_BYTES);

        return new PublicKeyBytes(secret, uncompressed);
    }

    public Sha256Bytes[] getSha256Bytes() {
        Sha256Bytes[] sha256Bytes = new Sha256Bytes[workSize];
        for (int currentWorkItem = 0; currentWorkItem < workSize; currentWorkItem++) {
            int workItemOffsetInByteBuffer = TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256 * currentWorkItem;
            byte[] resultBytesFromWorkItem = retrieveBytesFromResult(workItemOffsetInByteBuffer, TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256);
            sha256Bytes[currentWorkItem] = new Sha256Bytes(resultBytesFromWorkItem);
        }
        return sha256Bytes;
    }

    private byte[] retrieveBytesFromResult(int byteBufferOffset, int numberOfBytesToRetrieve) {
        // each 32 bits are stored in 4 bytes in a reversed order
        int swapGroupNumBytes = Sha256Bytes.ONE_SHA256_NUM_BYTES / PublicKeyBytes.BITS_PER_BYTE;
        byte[] retrievedBytesInCorrectOrder = new byte[numberOfBytesToRetrieve];
        int[] readIndexes = createReadIndices(numberOfBytesToRetrieve, swapGroupNumBytes);
        for (int i = 0; i < numberOfBytesToRetrieve; i++) {
            retrievedBytesInCorrectOrder[i] = result.get(byteBufferOffset + readIndexes[i]);
        }
        return retrievedBytesInCorrectOrder;
    }

    /**
     * Will create an array with indexes to deal with reversed elements in another array.
     * Example: result = 2, 1, 0, 5, 4, 3, 8, 7, 6 when each group of 3 indices are reversed
     *
     * @param totalNumberOfIndices     how many indices should be created
     * @param reversedIndicesGroupSize size of groups of reveresed indices
     * @return array containing the correct indices
     */
    protected static int[] createReadIndices(int totalNumberOfIndices, int reversedIndicesGroupSize) {
        int[] indexArray = new int[totalNumberOfIndices];
        int groupStartIndex = (reversedIndicesGroupSize - 1);
        int groupEndIndex = 0;
        int step = groupStartIndex;
        for (int i = 0; i < totalNumberOfIndices; i++) {
            indexArray[i] = step;
            step--;
            if (step < groupEndIndex) {
                groupStartIndex += reversedIndicesGroupSize;
                groupEndIndex += reversedIndicesGroupSize;
                step = groupStartIndex;
            }
        }
        return indexArray;
    }
}