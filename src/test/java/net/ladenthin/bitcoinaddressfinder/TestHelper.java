package net.ladenthin.bitcoinaddressfinder;

import com.google.common.hash.Hashing;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.hamcrest.Matchers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

/**
 * Helper class including several utility methods for better testing of {@link OpenCLContext}.
 */
public class TestHelper {

    public static final int PRIVATE_KEY_MAX_BIT_LENGTH = 256;
    public static final int HEX_RADIX = 16;
    public static final int BINARY_RADIX = 2;

    /**
     * Creates and initializes an {@link OpenCLContext} for testing.
     *
     * @param chunkMode   If the {@link OpenCLContext} should use the <code>chunkMode</code> for private keys
     * @param kernelMode  With what <code>kernelMode</code> the {@link OpenCLContext} should run
     * @param gridNumBits Determines the number of bits to be shifted left to calculate the <code>workSize</code>
     * @return {@link OpenCLContext}
     */
    public static OpenCLContext createOpenCLContext(boolean chunkMode, int kernelMode, int gridNumBits) {
        new OpenCLPlatformAssume().assumeOpenCLLibraryLoadableAndOneOpenCL2_0OrGreaterDeviceAvailable();
        CProducerOpenCL producerOpenCL = new CProducerOpenCL();
        producerOpenCL.gridNumBits = gridNumBits;
        producerOpenCL.chunkMode = chunkMode;
        producerOpenCL.kernelMode = kernelMode;
        OpenCLContext openCLContext = new OpenCLContext(producerOpenCL);

        try {
            openCLContext.init();
        } catch (IOException | UnknownKernelModeException e) {
            throw new RuntimeException(e);
        }

        return openCLContext;
    }

    /**
     * Generates an array of random private keys.
     *
     * @param number of private keys to be generated
     * @return array of {@link BigInteger}s storing the generated private keys
     */
    public static BigInteger[] generateRandomPrivateKeys(int number) {
        List<BigInteger> privateKeysList = new LinkedList<>();
        while (privateKeysList.size() < number) {
            BigInteger candidate = KeyUtility.createSecret(PRIVATE_KEY_MAX_BIT_LENGTH, new SecureRandom());
            if (validBitcoinPrivateKey(candidate)) {
                privateKeysList.add(candidate);
            }
        }
        BigInteger[] privateKeysArray = new BigInteger[number];
        for (int i = 0; i < number; i++) {
            privateKeysArray[i] = privateKeysList.get(i);
        }
        return privateKeysArray;
    }

    /**
     * Validates if the given private key is valid in regard to BITCOIN.
     *
     * @param candidate to be validated
     * @return <code>true</code> if the given private key is valid, <code>false</code> otherwise
     */
    @SuppressWarnings("RedundantIfStatement")
    public static boolean validBitcoinPrivateKey(BigInteger candidate) {
        // Check if the private key is within the valid range
        BigInteger minPrivateKey = BigInteger.ONE;
        BigInteger maxPrivateKey = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", HEX_RADIX);
        if (!(candidate.compareTo(minPrivateKey) >= 0 && candidate.compareTo(maxPrivateKey) <= 0)) {
            return false;
        }
        if (candidate.toString(BINARY_RADIX).length() != PublicKeyBytes.PRIVATE_KEY_MAX_NUM_BITS) {
            return false;
        }
        return true;
    }

    /**
     * Calculates the uncompressed public key from a given private key.
     *
     * @param privateKey As a {@link BigInteger}
     * @return The uncompressed public key as a hex {@link String}
     */
    public static String calculatePublicKeyAsHexStringFromPrivateKey(BigInteger privateKey) {
        return Hex.encodeHexString(calculatePublicKeyAsBytesFromPrivateKey(privateKey));
    }

    /**
     * Calculates the uncompressed public key from a given private key.
     *
     * @param privateKey As a {@link BigInteger}
     * @return The uncompressed public key as a byte array
     */
    public static byte[] calculatePublicKeyAsBytesFromPrivateKey(BigInteger privateKey) {
        return ECKey.publicKeyFromPrivate(privateKey, false);
    }

    /**
     * Hashes a given byte array with SHA-256.
     *
     * @param digest To be hashed
     * @return Hashed byte array with the size of 32 bytes
     */
    public static byte[] calculateSha256FromByteArray(byte[] digest) {
        return Hashing.sha256().hashBytes(digest).asBytes();
    }

    /**
     * Hashes a given byte array with RIPEMD-160.
     *
     * @param digest To be hashed
     * @return Hashed byte array with the size of 20 bytes
     */
    public static byte[] calculateRipemd160FromByteArray(byte[] input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(input, 0, input.length);
        byte[] out = new byte[Ripemd160Bytes.RIPEMD160_LENGTH_IN_BYTES];
        digest.doFinal(out, 0);
        return out;
    }

    public static BigInteger[] calculatePrivateKeyChunkFromSinglePrivateKey(BigInteger singlePrivateKey, int arraySize) {
        BigInteger[] chunk = new BigInteger[arraySize];
        chunk[0] = singlePrivateKey;
        for (int i = 1; i < chunk.length; i++) {
            chunk[i] = bitwiseOrOperationWithLast32Bits(singlePrivateKey, i);
        }
        return chunk;
    }

    public static byte[] calculateDigestWithVersionByteFromByteArray(byte[] byteArray) {
        byte[] digestWithVersionByte = new byte[byteArray.length + 1];
        digestWithVersionByte[0] = 0;
        System.arraycopy(byteArray, 0, digestWithVersionByte, 1, byteArray.length);
        return digestWithVersionByte;
    }

    /**
     * Calculates an address from a given RIPEMD-160 hash.
     *
     * @param ripemd160 To calculate the address from
     * @return The address as a byte array or <code>null</code> if the length of the RIPEMD-160 is not equal 20 bytes
     */
    public static byte[] calculateAddressFromRipemd160(byte[] ripemd160) {
        if (ripemd160.length != ResultBytes.NUM_BYTES_RIPEMD160) {
            return null;
        }
        byte[] address = new byte[ResultBytes.NUM_BYTES_ADDRESS];
        byte[] ripemd160WithVersionByte = calculateDigestWithVersionByteFromByteArray(ripemd160);
        System.arraycopy(ripemd160WithVersionByte, 0, address, 0, ripemd160WithVersionByte.length);
        byte[] secondSha256Hash = calculateSha256FromByteArray(ripemd160WithVersionByte);
        byte[] thirdSha256Hash = calculateSha256FromByteArray(secondSha256Hash);
        address[21] = thirdSha256Hash[0];
        address[22] = thirdSha256Hash[1];
        address[23] = thirdSha256Hash[2];
        address[24] = thirdSha256Hash[3];
        return address;
    }

    /*
     * Method written by OpenAI/ChatGPT.
     *
     * Simulates the or operation in OpenCL when using the chunk mode
     * This method will perform a bitwise OR-operation with the last 32 bits of a given BigInteger with the given value
     *
     * BigInteger number: The secret key as a BigInteger
     *         int value: The value which in OpenCL would be the global_id
     */
    private static BigInteger bitwiseOrOperationWithLast32Bits(BigInteger number, int value) {
        // Mask for the last 32 bits
        BigInteger mask = BigInteger.valueOf(0xFFFFFFFFL);

        // Extract the last 32 bits as a BigInteger
        BigInteger last32Bits = number.and(mask);

        // Perform bitwise OR operation with the given value
        BigInteger result = last32Bits.or(BigInteger.valueOf(value));

        // Update the last 32 bits in the number with the modified value
        return number.and(mask.not()).or(result);
    }

    /**
     * Transforms a hex {@link String} into an array of {@link BigInteger}s.
     *
     * @param hexString To be transformed into an array of {@link BigInteger}s
     * @return The {@link BigInteger} array of the given hex {@link String}
     */
    public static BigInteger[] transformHexStringToBigIntegerArray(String hexString) {
        return transformHexStringArrayToBigIntegerArray(new String[]{hexString});
    }

    /**
     * Transforms an array of hex {@link String}s into an array of {@link BigInteger}s.
     *
     * @param hexStringArray To be transformed into an array of {@link BigInteger}s
     * @return The {@link BigInteger} array of the given hex {@link String} array
     */
    public static BigInteger[] transformHexStringArrayToBigIntegerArray(String[] hexStringArray) {
        BigInteger[] bigIntegerArray = new BigInteger[hexStringArray.length];
        for (int i = 0; i < hexStringArray.length; i++) {
            bigIntegerArray[i] = new BigInteger(hexStringArray[i], HEX_RADIX);
        }
        return bigIntegerArray;
    }

    /*
     * Method written by OpenAI/ChatGPT.
     * Prompt: "I need a java method to turn a hexString to a byte array".
     */

    /**
     * Transforms a hex in a {@link String} into a byte array.
     *
     * @param hexString To be transformed into a byte array
     * @return The byte array of the given hex {@link String}
     */
    public static byte[] transformHexStringToBytes(String hexString) {
        int length = hexString.length();
        byte[] byteArray = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), HEX_RADIX) << 4) + Character.digit(hexString.charAt(i + 1), HEX_RADIX));
        }
        return byteArray;
    }

    /**
     * Transforms a {@link String} into a byte array.
     *
     * @param input To be transformed into a byte array
     * @return The byte array of the given {@link String}
     */
    public static byte[] transformStringToBytes(String input) {
        return input.getBytes();
    }

    /**
     * Transforms a {@link BigInteger} into a hex {@link String}.
     *
     * @param bigInteger To be transformed into a hex {@link String}
     * @return The hexadecimal representation of the given {@link BigInteger}
     */
    public static String transformBigIntegerToHexString(BigInteger bigInteger) {
        return bigInteger.toString(HEX_RADIX);
    }

    public static byte[] transformPrivateKeyFromBigIntegerToByteArray(BigInteger bigInteger) {
        byte[] bigIntegerAsBytes = bigInteger.toByteArray();
        int srcOffset = 0;
        if ((bigIntegerAsBytes.length > ResultBytes.NUM_BYTES_PRIVATE_KEY) && (bigIntegerAsBytes[0] == 0)) {
            srcOffset = bigIntegerAsBytes.length - ResultBytes.NUM_BYTES_PRIVATE_KEY;
        }
        byte[] resultBytes = new byte[bigIntegerAsBytes.length - srcOffset];
        System.arraycopy(bigIntegerAsBytes, srcOffset, resultBytes, 0, (bigIntegerAsBytes.length - srcOffset));
        return resultBytes;
    }

    /**
     * Transforms {@link PublicKeyBytes} into a hex {@link String}.
     *
     * @param publicKeyBytes To be transformed into a hex {@link String}
     * @return The hexadecimal representation of the given {@link PublicKeyBytes}
     */
    public static String transformPublicKeyBytesToHexString(PublicKeyBytes publicKeyBytes) {
        return Hex.encodeHexString(publicKeyBytes.getUncompressed());
    }

    /**
     * Transforms a given array of bytes into a hex {@link String}.
     *
     * @param bytes To be transformed into a hex {@link String}
     * @return The hexadecimal representation of the given bytes
     */
    public static String transformBytesToHexString(byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }

    /**
     * Transforms a given array of bytes into a {@link String} encoded with Base58.
     *
     * @param addressBytes To be transformed into a Base58 {@link String}
     * @return The Base58 encoded representation of the given bytes
     */
    public static String transformAddressBytesToBase58String(byte[] addressBytes) {
        return Base58.encode(addressBytes);
    }

    /**
     * Stores the private keys and their public keys in a {@link HashMap} as hex {@link String}s.
     *
     * @param privateKeys Array of {@link BigInteger} containing private keys
     * @param publicKeys  Array of {@link BigInteger} containing public keys
     * @return {@link HashMap} containing the private key and its public key both as hex {@link String}s
     * or <code>null</code> if the length of both given arrays are not equal
     */
    public static Map<String, String> createResultedMapOfPrivateKeysAndTheirPublicKeys(BigInteger[] privateKeys, PublicKeyBytes[] publicKeys) {
        Map<String, String> map = new HashMap<>();
        if (privateKeys.length != publicKeys.length) {
            return null;
        }
        for (int i = 0; i < privateKeys.length; i++) {
            String privateKeyHexString = transformBigIntegerToHexString(privateKeys[i]);
            String publicKeyHexString = transformPublicKeyBytesToHexString(publicKeys[i]);
            map.put(privateKeyHexString, publicKeyHexString);
        }
        return map;
    }

    /**
     * Stores the public keys and their SHA-256 hashes (both initially stored in the given {@link Sha256Bytes} array)
     * in a {@link HashMap} as hex {@link String}s.
     *
     * @param sha256Hashes Array of {@link Sha256Bytes} containing the public keys and their SHA-256 hashes
     * @return {@link HashMap} containing the public key and its SHA-256 hash both as hex {@link String}s
     */
    public static Map<String, String> createResultedMapOfPublicKeysAndTheirSha256Hashes(Sha256Bytes[] sha256Hashes) {
        Map<String, String> map = new HashMap<>();
        for (Sha256Bytes sha256Bytes : sha256Hashes) {
            byte[] publicKeyBytes = sha256Bytes.getPublicKeyUncompressed();
            String publicKeyHexString = transformBytesToHexString(publicKeyBytes);
            byte[] firstSha256Bytes = sha256Bytes.getFirstSha256Bytes();
            String firstSha256String = transformBytesToHexString(firstSha256Bytes);
            map.put(publicKeyHexString, firstSha256String);
        }
        return map;
    }

    /**
     * Stores both SHA-256 hashes (both initially stored in the given {@link Sha256Bytes} array)
     * in a {@link HashMap} as hex {@link String}s.
     *
     * @param sha256Hashes Array of {@link Sha256Bytes} containing both SHA-256 hashes
     * @return {@link HashMap} containing both SHA-256 hashes as hex {@link String}s
     */
    public static Map<String, String> createResultedMapOfSha256HashesAndTheirSha256Hashes(Sha256Bytes[] sha256Hashes) {
        Map<String, String> map = new HashMap<>();
        for (Sha256Bytes sha256Bytes : sha256Hashes) {
            byte[] firstSha256Bytes = sha256Bytes.getFirstSha256Bytes();
            String firstSha256String = transformBytesToHexString(firstSha256Bytes);
            byte[] secondSha256Bytes = sha256Bytes.getSecondSha256Bytes();
            String secondSha256String = transformBytesToHexString(secondSha256Bytes);
            map.put(firstSha256String, secondSha256String);
        }
        return map;
    }

    /**
     * Stores the SHA-256 hash and its RIPEMD-160 hash (both initially stored in the given {@link Ripemd160Bytes} array)
     * in a {@link HashMap} as hex {@link String}s.
     *
     * @param ripemd16Hashes Array of {@link Ripemd160Bytes} containing both SHA-256 and RIPEMD-160 hashes
     * @return {@link HashMap} containing both RIPEMD-160 hashes as hex {@link String}s
     */
    public static Map<String, String> createResultedMapOfSha256HashesAndTheirRipemd160Hashes(Ripemd160Bytes[] ripemd16Hashes) {
        Map<String, String> map = new HashMap<>();
        for (Ripemd160Bytes ripemd160Bytes : ripemd16Hashes) {
            byte[] sha256Bytes = ripemd160Bytes.getSha256Bytes();
            String sha256HexString = transformBytesToHexString(sha256Bytes);
            byte[] ripemd160BytesArray = ripemd160Bytes.getRipemd160Bytes();
            String ripemd160HexString = transformBytesToHexString(ripemd160BytesArray);
            map.put(sha256HexString, ripemd160HexString);
        }
        return map;
    }

    /**
     * Generates the public keys for each given private key and stores both as hex {@link String}s.
     *
     * @param privateKeys Array of {@link BigInteger} containing private keys
     * @return {@link HashMap} containing the private keys and their public keys both as hex {@link String}s
     */
    public static Map<String, String> createExpectedMapOfPrivateKeysToPublicKeys(BigInteger[] privateKeys) {
        Map<String, String> map = new HashMap<>();
        for (BigInteger privateKey : privateKeys) {
            String privateKeyHexString = transformBigIntegerToHexString(privateKey);
            String publicKeyHexString = calculatePublicKeyAsHexStringFromPrivateKey(privateKey);
            map.put(privateKeyHexString, publicKeyHexString);
        }
        return map;
    }

    /**
     * Generates the SHA-256 hashes for each public key and stores both as hex {@link String}s.
     *
     * @param publicKeys Array of {@link BigInteger} containing public keys
     * @return {@link HashMap} containing the public keys and their SHA-256 both as hex {@link String}s
     */
    public static Map<String, String> createExpectedMapOfPublicKeysToSha256Hashes(PublicKeyBytes[] publicKeys) {
        Map<String, String> map = new HashMap<>();
        for (PublicKeyBytes publicKey : publicKeys) {
            String publicKeyHexString = transformPublicKeyBytesToHexString(publicKey);
            byte[] publicKeyBytes = publicKey.getUncompressed();
            byte[] sha256Bytes = calculateSha256FromByteArray(publicKeyBytes);
            String sha256HexString = transformBytesToHexString(sha256Bytes);
            map.put(publicKeyHexString, sha256HexString);
        }
        return map;
    }

    /**
     * Generates the SHA-256 hashes for each first SHA-256 hash and stores both as hex {@link String}s.
     *
     * @param sha256Hashes Array of {@link Sha256Bytes} containing SHA-256 hashes
     * @return {@link HashMap} containing the first SHA-256 and the calculated second SHA-256 hash as hex {@link String}s
     */
    public static Map<String, String> createExpectedMapOfSha256HashesToSha256Hases(Sha256Bytes[] sha256Hashes) {
        Map<String, String> map = new HashMap<>();
        for (Sha256Bytes sha256Bytes : sha256Hashes) {
            byte[] firstSha256HashBytes = sha256Bytes.getFirstSha256Bytes();
            String firstSha256HashHexString = transformBytesToHexString(firstSha256HashBytes);
            byte[] secondSha256HashBytes = calculateSha256FromByteArray(firstSha256HashBytes);
            String secondSha256HashHexString = transformBytesToHexString(secondSha256HashBytes);
            map.put(firstSha256HashHexString, secondSha256HashHexString);
        }
        return map;
    }

    /**
     * Generates the RIPEMD-160 hashes for each SHA-256 hash and stores both as hex {@link String}s.
     *
     * @param sha256Hashes Array of {@link Sha256Bytes} containing SHA-256 hashes
     * @return {@link HashMap} containing the SHA-256 and the calculated RIPEMD-160 hash as hex {@link String}s
     */
    public static Map<String, String> createExpectedMapOfSha256HashesToRipemd160Hashes(Sha256Bytes[] sha256Hashes) {
        Map<String, String> map = new HashMap<>();
        for (Sha256Bytes sha256Bytes : sha256Hashes) {
            byte[] sha256HashBytes = sha256Bytes.getFirstSha256Bytes();
            String firstSha256HashHexString = transformBytesToHexString(sha256HashBytes);
            byte[] ripemd160Bytes = calculateRipemd160FromByteArray(sha256HashBytes);
            String ripemd160HexString = transformBytesToHexString(ripemd160Bytes);
            map.put(firstSha256HashHexString, ripemd160HexString);
        }
        return map;
    }

    /**
     * Will generate all expecting results for each given private key and by considering the <code>kernelMode</code>
     *
     * @param privateKeys As base for generating all expected values for each {@link ResultBytes}.
     * @param kernelMode  To set all not expecting byte arrays to <code>{0, 0, 0,...}</code>.
     * @return Array containing {@link ResultBytes} with all expecting values.
     */
    public static ResultBytes[] createExpectedResultBytesFromPrivateKeys(BigInteger[] privateKeys, int kernelMode) {
        int size = privateKeys.length;

        ResultBytes[] expectedResultBytes = new ResultBytes[size];

        for (int i = 0; i < size; i++) {
            byte[] expectedResultBuffer = new byte[ResultBytes.NUM_BYTES_TOTAL_UNTIL_ADDRESS];

            byte[] privateKey = transformPrivateKeyFromBigIntegerToByteArray(privateKeys[i]);
            System.arraycopy(privateKey, 0, expectedResultBuffer, 0, ResultBytes.NUM_BYTES_PRIVATE_KEY);

            byte[] expectedPublicKey = calculatePublicKeyAsBytesFromPrivateKey(privateKeys[i]);
            System.arraycopy(expectedPublicKey, 0, expectedResultBuffer, ResultBytes.NUM_BYTES_PRIVATE_KEY, ResultBytes.NUM_BYTES_PUBLIC_KEY);

            byte[] expectedFirstSha256 = calculateSha256FromByteArray(expectedPublicKey);
            System.arraycopy(expectedFirstSha256, 0, expectedResultBuffer, ResultBytes.NUM_BYTES_TOTAL_UNTIL_PUBLIC_KEY, ResultBytes.NUM_BYTES_SHA256);

            byte[] expectedRipemd160 = calculateRipemd160FromByteArray(expectedFirstSha256);
            System.arraycopy(expectedRipemd160, 0, expectedResultBuffer, ResultBytes.NUM_BYTES_TOTAL_UNTIL_1ST_SHA256, ResultBytes.NUM_BYTES_RIPEMD160);

            byte[] expectedRipemd160WithVersionByte = calculateDigestWithVersionByteFromByteArray(expectedRipemd160);
            byte[] expectedSecondSha256 = calculateSha256FromByteArray(expectedRipemd160WithVersionByte);
            System.arraycopy(expectedSecondSha256, 0, expectedResultBuffer, ResultBytes.NUM_BYTES_TOTAL_UNTIL_RIPEMD160, ResultBytes.NUM_BYTES_SHA256);

            byte[] expectedThirdSha256Hash = calculateSha256FromByteArray(expectedSecondSha256);
            System.arraycopy(expectedThirdSha256Hash, 0, expectedResultBuffer, ResultBytes.NUM_BYTES_TOTAL_UNTIL_2ND_SHA256, ResultBytes.NUM_BYTES_SHA256);

            byte[] expectedAddress = calculateAddressFromRipemd160(expectedRipemd160);
            System.arraycopy(expectedAddress, 0, expectedResultBuffer, ResultBytes.NUM_BYTES_TOTAL_UNTIL_3RD_SHA256, ResultBytes.NUM_BYTES_ADDRESS);

            ResultBytesFactory factory = new ResultBytesFactory();
            factory.setResultBufferBytes(expectedResultBuffer);
            factory.setKernelMode(kernelMode);
            expectedResultBytes[i] = factory.createResultBytes();
        }
        return expectedResultBytes;
    }

    /**
     * Will generate all expecting addresses for each given private key.
     *
     * @param privateKeys As base for generating all expected addresses for each {@link AddressBytes}.
     * @return Array containing {@link AddressBytes} with all expecting addresses.
     */
    public static AddressBytes[] createExpectedAddressBytesFromPrivateKeys(BigInteger[] privateKeys) {
        AddressBytes[] expectedAddressBytes = new AddressBytes[privateKeys.length];
        for (int i = 0; i < privateKeys.length; i++) {
            expectedAddressBytes[i] = createExpectedAddressBytesFromPrivateKey(privateKeys[i]);
        }
        return expectedAddressBytes;
    }

    private static AddressBytes createExpectedAddressBytesFromPrivateKey(BigInteger privateKey) {
        return new AddressBytes(transformPrivateKeyFromBigIntegerToByteArray(privateKey), calculateAddressFromPrivateKey(privateKey));
    }

    /**
     * @param singlePrivateKey as base for generating expected values
     * @param chunkSize        size of chunk to be created
     * @return Array containing {@link ResultBytes} with all expecting values
     */
    public static ResultBytes[] createExpectedResultBytesFromSinglePrivateKey(BigInteger singlePrivateKey, int chunkSize, int kernelMode) {
        BigInteger[] privateKeysChunk = calculatePrivateKeyChunkFromSinglePrivateKey(singlePrivateKey, chunkSize);
        return createExpectedResultBytesFromPrivateKeys(privateKeysChunk, kernelMode);
    }

    /**
     * Will generate all expecting addresses for each given private key simulating the chunk mode.
     *
     * @param singlePrivateKey as base for generating expected values
     * @param chunkSize        size of chunk to be created
     * @return Array containing {@link AddressBytes} with all expecting values
     */
    public static AddressBytes[] createExpectedAddressBytesChunkFromPrivateKey(BigInteger singlePrivateKey, int chunkSize) {
        BigInteger[] privateKeysChunk = calculatePrivateKeyChunkFromSinglePrivateKey(singlePrivateKey, chunkSize);
        return createExpectedAddressBytesFromPrivateKeys(privateKeysChunk);
    }

    public static <K, V> ActualMap<K, V> assertThatKeyMap(Map<K, V> actualMap) {
        return new ActualMap<>(actualMap);
    }

    /**
     * Calculates the address from a given private key.
     *
     * @param privateKey To derive the address from.
     * @return address Derived from the given private key.
     */
    public static byte[] calculateAddressFromPrivateKey(BigInteger privateKey) {
        byte[] publicKey = calculatePublicKeyAsBytesFromPrivateKey(privateKey);
        byte[] firstSha256 = calculateSha256FromByteArray(publicKey);
        byte[] ripemd160 = calculateRipemd160FromByteArray(firstSha256);
        return calculateAddressFromRipemd160(ripemd160);
    }

    /**
     * Map storing actual values for better test assertions. Compares size and if both are equal.
     *
     * @param <K> the key type
     * @param <V> the value type
     */
    public static class ActualMap<K, V> {

        private final Map<K, V> actualMap;

        private ActualMap(Map<K, V> actualMap) {
            assertThat(actualMap, Matchers.notNullValue());
            this.actualMap = actualMap;
        }

        public void isEqualTo(Map<K, V> expectedMap) {
            assertThat(expectedMap, Matchers.notNullValue());
            assertThat("None identical length of both maps!", actualMap.size(), is(equalTo(expectedMap.size())));
            Set<K> expectedKeys = expectedMap.keySet();
            for (K expectedKey : expectedKeys) {
                assertThat("Contains key", true, is(actualMap.containsKey(expectedKey)));
            }
            int i = 0;
            for (K expectedKey : expectedKeys) {
                String reason = "Current Element: " + i + "/" + (actualMap.size() - 1);
                final V actualValue = actualMap.get(expectedKey);
                final V expectedValue = expectedMap.get(expectedKey);
                reason += "\n\t  expectedKey = " + expectedKey.toString();
                reason += "\n\texpectedValue = " + expectedValue.toString();
                reason += "\n\t  actualValue = " + actualValue.toString();
                assertThat(reason, actualValue, is(equalTo(expectedValue)));
                System.out.println(reason);
                i++;
            }
        }
    }

    public static ActualResultBytesArray assertThatResultBytesArray(ResultBytes[] actual) {
        return new ActualResultBytesArray(actual);
    }

    public static ActualAddressBytesArray assertThatAddressBytesArray(AddressBytes[] actual) {
        return new ActualAddressBytesArray(actual);
    }

    /**
     * Array storing actual {@link ResultBytes} for better test assertions. Compares size and if elements in both are equal. Does not consider identical order of elements.
     */
    public static class ActualResultBytesArray {

        private final List<ResultBytes> actual;

        public ActualResultBytesArray(ResultBytes[] actual) {
            assertThat(actual, Matchers.notNullValue());
            this.actual = Arrays.asList(actual);
        }

        public void isEqualTo(ResultBytes[] expected) {
            assertThat(expected, Matchers.notNullValue());
            assertThat("None identical length of both arrays!", actual.size(), is(equalTo(expected.length)));
            int i = 0;
            boolean elemExists;
            for (ResultBytes expectedElem : expected) {
                elemExists = false;
                String reason = "Current expected ResultBytes: " + i + "/" + (expected.length - 1);
                for (ResultBytes actualElem : actual) {
                    if (Arrays.equals(expectedElem.getPrivateKeyBytes(), actualElem.getPrivateKeyBytes())) {
                        elemExists = true;
                        reason += "\n\t        expected private key = " + Arrays.toString(expectedElem.getPrivateKeyBytes());
                        reason += "\n\t          actual private key = " + Arrays.toString(actualElem.getPrivateKeyBytes());
                        reason += "\n\t         expected public key = " + Arrays.toString(expectedElem.getPublicKeyBytes());
                        reason += "\n\t           actual public key = " + Arrays.toString(actualElem.getPublicKeyBytes());
                        reason += "\n\t expected first SHA-256 hash = " + Arrays.toString(expectedElem.getFirstSha256BytesBytes());
                        reason += "\n\t   actual first SHA-256 hash = " + Arrays.toString(actualElem.getFirstSha256BytesBytes());
                        reason += "\n\t    expected RIPEMD-160 hash = " + Arrays.toString(expectedElem.getRipemd160BytesBytes());
                        reason += "\n\t      actual RIPEMD-160 hash = " + Arrays.toString(actualElem.getRipemd160BytesBytes());
                        reason += "\n\texpected second SHA-256 hash = " + Arrays.toString(expectedElem.getSecondSha256Bytes());
                        reason += "\n\t  actual second SHA-256 hash = " + Arrays.toString(actualElem.getSecondSha256Bytes());
                        reason += "\n\t expected third SHA-256 hash = " + Arrays.toString(expectedElem.getThirdSha256Bytes());
                        reason += "\n\t   actual third SHA-256 hash = " + Arrays.toString(actualElem.getThirdSha256Bytes());
                        reason += "\n\t            expected address = " + Arrays.toString(expectedElem.getAddressBytes());
                        reason += "\n\t              actual address = " + Arrays.toString(actualElem.getAddressBytes());
                        reason += "\n\t   expected address (BASE58) = " + transformAddressBytesToBase58String(expectedElem.getAddressBytes());
                        reason += "\n\t     actual address (BASE58) = " + transformAddressBytesToBase58String(actualElem.getAddressBytes());
                        assertThat(reason, actualElem, is(equalTo(expectedElem)));
                        System.out.println(reason);
                        break;
                    }
                }
                assertThat("Actual ResultBytesArray does NOT contain expected ResultBytes with private key: " + Arrays.toString(expectedElem.getPrivateKeyBytes()), elemExists, is(true));
                i++;
            }
        }
    }

    /**
     * Array storing actual {@link AddressBytes} for better test assertions. Compares size and if elements in both are equal. Does not consider identical order of elements.
     */
    public static class ActualAddressBytesArray {

        private final List<AddressBytes> actual;

        public ActualAddressBytesArray(AddressBytes[] actual) {
            assertThat(actual, Matchers.notNullValue());
            this.actual = Arrays.asList(actual);
        }

        public void isEqualTo(AddressBytes[] expected) {
            assertThat(expected, Matchers.notNullValue());
            assertThat("None identical length of both arrays!", actual.size(), is(equalTo(expected.length)));
            int i = 0;
            boolean elemExists;
            for (AddressBytes expectedElem : expected) {
                elemExists = false;
                String reason = "Current expected ResultBytes: " + i + "/" + (expected.length - 1);
                for (AddressBytes actualElem : actual) {
                    if (Arrays.equals(expectedElem.getPrivateKey(), actualElem.getPrivateKey())) {
                        elemExists = true;
                        reason += "\n\t        expected private key = " + Arrays.toString(expectedElem.getPrivateKey());
                        reason += "\n\t          actual private key = " + Arrays.toString(actualElem.getPrivateKey());
                        reason += "\n\t   expected address (BASE58) = " + transformAddressBytesToBase58String(expectedElem.getAddress());
                        reason += "\n\t     actual address (BASE58) = " + transformAddressBytesToBase58String(actualElem.getAddress());
                        assertThat(reason, actualElem, is(equalTo(expectedElem)));
                        System.out.println(reason);
                        break;
                    }
                }
                assertThat("Actual AddressBytesArray does NOT contain expected AddressBytes with private key: " + Arrays.toString(expectedElem.getPrivateKey()), elemExists, is(true));
                i++;
            }
        }
    }
}