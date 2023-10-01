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

    private final ByteBufferUtility byteBufferUtility = new ByteBufferUtility(true);
    private final BigInteger[] secretKeys;
    private final int workSize;
    private final boolean chunkMode;
    private final int kernelMode;
    private ByteBuffer result;

    OpenCLGridResult(BigInteger[] secretKeys, int workSize, ByteBuffer result, boolean chunkMode, int kernelMode) {
        this.secretKeys = secretKeys;
        this.workSize = workSize;
        this.result = result;
        this.chunkMode = chunkMode;
        this.kernelMode = kernelMode;
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
        keyOffsetInByteBuffer = PublicKeyBytes.TWO_COORDINATES_NUM_BYTES * keyNumber;

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

    /**
     * This method will retrieve all resulting calculations from the {@link OpenCLGridResult} and store them in a {@link ResultBytes} array.
     *
     * @return array of {@link ResultBytes}
     */
    public ResultBytes[] getResultBytes() {
        ResultBytes[] resultBytes = new ResultBytes[workSize];
        for (int i = 0; i < workSize; i++) {
            resultBytes[i] = retrieveResultBytesFromWorkItem(i);
        }
        return resultBytes;
    }

    public AddressBytes[] getAddressBytes() {
        AddressBytes[] addressBytes = new AddressBytes[workSize];
        for (int i = 0; i < workSize; i++) {
            addressBytes[i] = retrieveAddressBytesFromWorkItem(i);
        }
        return addressBytes;
    }

    public Ripemd160Bytes[] getRipemd160Bytes() {
        // TODO to be implemented...
    }

    private ResultBytes retrieveResultBytesFromWorkItem(int workItemId) {
        byte[] workItemResultBytes = retrieveWorkItemResultBytesFromResultBuffer(workItemId);
        ResultBytesFactory factory = new ResultBytesFactory();
        factory.setResultBufferBytes(workItemResultBytes);
        factory.setKernelMode(kernelMode);
        return factory.createResultBytes();
    }

    private AddressBytes retrieveAddressBytesFromWorkItem(int workItemId) {
        byte[] workItemResultBytes = retrieveWorkItemResultBytesFromResultBuffer(workItemId);
        AddressBytesFactory factory = new AddressBytesFactory();
        factory.setResultBufferBytes(workItemResultBytes);
        factory.setKernelMode(kernelMode);
        return factory.createAddressBytes();
    }

    private byte[] retrieveWorkItemResultBytesFromResultBuffer(int workItemId) {
        int workItemResultSize = result.capacity() / workSize;
        byte[] workItemResultBytes = new byte[workItemResultSize];
        int workItemResultBufferOffset = workItemId * workItemResultSize;
        for (int i = 0; i < workItemResultSize; i++) {
            workItemResultBytes[i] = result.get(workItemResultBufferOffset + i);
        }
        return workItemResultBytes;
    }
}