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
    public static final int TWO_COORDINATES_NUM_BYTES_SHA256_RIPEMD160 = PublicKeyBytes.TWO_COORDINATES_NUM_BYTES + Sha256Bytes.ONE_SHA256_NUM_BYTES + Ripemd160Bytes.RIPEMD160_LENGTH_IN_BYTES;

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
        } else if (kernelMode == OpenCLContext.GEN_RIPEMD160_MODE) {
            keyOffsetInByteBuffer = TWO_COORDINATES_NUM_BYTES_SHA256_RIPEMD160 * keyNumber;
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

    /**
     * This method will retrieve the <strong> uncompressed public key with parity</strong>,
     * the first SHA-256 hash of this key and the second SHA-256 hash from the previous hash
     * from the {@link OpenCLGridResult} and store them in {@link Sha256Bytes} array.
     *
     * @return array of {@link Sha256Bytes}
     */
    public Sha256Bytes[] getSha256Bytes() {
        Sha256Bytes[] sha256Bytes;

        if (chunkMode) {
            sha256Bytes = getSha256BytesInChunkMode();
        } else {
            sha256Bytes = getSha256BytesInNonChunkMode();
        }

        return sha256Bytes;
    }

    private Sha256Bytes[] getSha256BytesInChunkMode() {
        Sha256Bytes[] sha256Bytes = new Sha256Bytes[workSize];
        for (int currentWorkItem = 0; currentWorkItem < workSize; currentWorkItem++) {
            PublicKeyBytes publicKeyBytes = getPublicKeyFromByteBufferXY(result, currentWorkItem, secretKeys[0]);
            sha256Bytes[currentWorkItem] = readBufferForSha256Bytes(currentWorkItem, publicKeyBytes.getUncompressed());
        }
        return sha256Bytes;
    }

    private Sha256Bytes[] getSha256BytesInNonChunkMode() {
        Sha256Bytes[] sha256Bytes = new Sha256Bytes[workSize];
        for (int currentWorkItem = (workSize - 1); currentWorkItem >= 0; currentWorkItem--) {
            PublicKeyBytes publicKeyBytes = getPublicKeyFromByteBufferXY(result, currentWorkItem, secretKeys[workSize - 1 - currentWorkItem]);
            sha256Bytes[currentWorkItem] = readBufferForSha256Bytes(currentWorkItem, publicKeyBytes.getUncompressed());
        }
        return sha256Bytes;
    }

    private Sha256Bytes readBufferForSha256Bytes(int currentWorkItem, byte[] pubKeyUncompressed) {
        int workItemOffsetInByteBuffer = TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256 * currentWorkItem;
        byte[] hash1hash2yx = new byte[TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256];
        int index = 0;
        for (int i = (TWO_COORDINATES_NUM_BYTES_DOUBLE_SHA256 - 1); i >= 0; i--) {
            hash1hash2yx[i] = result.get(workItemOffsetInByteBuffer + index);
            index++;
        }
        // copy first SHA-256 hash
        byte[] firstSha256Hash = new byte[Sha256Bytes.ONE_SHA256_NUM_BYTES];
        System.arraycopy(hash1hash2yx, Sha256Bytes.ONE_SHA256_NUM_BYTES, firstSha256Hash, 0,
                Sha256Bytes.ONE_SHA256_NUM_BYTES);

        // copy second SHA-256 hash
        byte[] secondSha256Hash = new byte[Sha256Bytes.ONE_SHA256_NUM_BYTES];
        System.arraycopy(hash1hash2yx, 0, secondSha256Hash, 0,
                Sha256Bytes.ONE_SHA256_NUM_BYTES);

        return new Sha256Bytes(pubKeyUncompressed, firstSha256Hash, secondSha256Hash);
    }

    /**
     * This method will retrieve the SHA-256 hash from the public key and the RIPEMD-160 hash of that SHA-256 hash
     * from the {@link OpenCLGridResult} and store them in a {@link Ripemd160Bytes} array.
     *
     * @return array of {@link Ripemd160Bytes}
     */
    public Ripemd160Bytes[] getRipemd160Bytes() {
        if (chunkMode) {
            return getRipemd160BytesInChunkMode();
        } else {
            return getRipemd160BytesInNonChunkMode();
        }
    }

    private Ripemd160Bytes[] getRipemd160BytesInChunkMode() {
        Ripemd160Bytes[] ripemd160Bytes = new Ripemd160Bytes[workSize];
        for (int currentWorkItem = 0; currentWorkItem < workSize; currentWorkItem++) {
            ripemd160Bytes[currentWorkItem] = readBufferForRipemd160Bytes(currentWorkItem);
        }
        return ripemd160Bytes;
    }

    private Ripemd160Bytes[] getRipemd160BytesInNonChunkMode() {
        // TODO impl method
        return null;
    }

    private Ripemd160Bytes readBufferForRipemd160Bytes(int currentWorkItem) {
        int workItemOffsetInByteBuffer = Ripemd160Bytes.RESULT_LENGTH_IN_BYTES * currentWorkItem;
        byte[] hash1hash2yx = new byte[Ripemd160Bytes.RESULT_LENGTH_IN_BYTES];
        int index = 0;
        for (int i = (Ripemd160Bytes.RESULT_LENGTH_IN_BYTES - 1); i >= 0; i--) {
            hash1hash2yx[i] = result.get(workItemOffsetInByteBuffer + index);
            index++;
        }
        // copy SHA-256 hash
        byte[] sha256Hash = new byte[Sha256Bytes.ONE_SHA256_NUM_BYTES];
        System.arraycopy(hash1hash2yx, Ripemd160Bytes.RIPEMD160_LENGTH_IN_BYTES, sha256Hash, 0,
                Sha256Bytes.ONE_SHA256_NUM_BYTES);

        // copy RIPEMD-160 hash
        byte[] ripemd160Hash = new byte[Ripemd160Bytes.RIPEMD160_LENGTH_IN_BYTES];
        System.arraycopy(hash1hash2yx, 0, ripemd160Hash, 0,
                Ripemd160Bytes.RIPEMD160_LENGTH_IN_BYTES);

        return new Ripemd160Bytes(sha256Hash, ripemd160Hash);
    }
}