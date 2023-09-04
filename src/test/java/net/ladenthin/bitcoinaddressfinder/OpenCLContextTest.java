package net.ladenthin.bitcoinaddressfinder;

import org.jocl.CL;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Map;

import static net.ladenthin.bitcoinaddressfinder.TestHelper.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

/**
 * Tests the calculation of an OpenClContext without considering the performance.
 */
public class OpenCLContextTest {

    public static final int CHUNK_SIZE = 256;

    private static final boolean CHUNK_MODE = true;
    private static final boolean NON_CHUNK_MODE = false;
    private static final int SHIFT_NONE = 0;
    private static final int SHIFT_8_BITS_FOR_256_CHUNK_SIZE = 8;
    private static final String PRIVATE_KEY_HEX_STRING = "c297e4944f46f3b9f04cf4b3984f49bd4ee40dec33991066fa15cdb227933400";
    private static final String PUBLIC_KEY_HEX_STRING = "04ccc8a095355a8479d9ef89eb6e435fb7fd9b2120dba38f71bf51a51f2fe66d6f64e30ee36de0a5691ad6d8036919ce8dc3ffb073510b8535675e103c045c6f44";
    private static final String ADDRESS_BASE58_STRING = "1GQAxeEwvNMT4G3QjKBRRjBxC6x4Pb9iQz";
    private static final String ERROR_CODE_SUCCESS = CL.stringFor_errorCode(CL.CL_SUCCESS);

    @Test
    public void test_generateSinglePublicKeyBytes_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE, SHIFT_NONE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes[] publicKeysResult = openCLGridResult.getPublicKeyBytes();
        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        String resultPublicKeyAsHexString = TestHelper.transformPublicKeyBytesToHexString(publicKeysResult[0]);
        assertThat(resultPublicKeyAsHexString, is(equalTo(PUBLIC_KEY_HEX_STRING)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSinglePublicKeyBytes_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        //arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE, SHIFT_NONE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes[] publicKeysResult = openCLGridResult.getPublicKeyBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        String resultPublicKeyAsHexString = TestHelper.transformPublicKeyBytesToHexString(publicKeysResult[0]);
        String expectedPublicKeyAsHexString = TestHelper.calculatePublicKeyAsHexStringFromPrivateKey(randomSinglePrivateKey[0]);
        assertThat(resultPublicKeyAsHexString, is(equalTo(expectedPublicKeyAsHexString)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256PublicKeyBytes_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        //arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes[] publicKeysResult = openCLGridResult.getPublicKeyBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeysResult);
        Map<String, String> expectedKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeysResult);
        assertThatKeyMap(resultKeysMap).isEqualTo(expectedKeysMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256PublicKeyBytes_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        //arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes[] publicKeysResult = openCLGridResult.getPublicKeyBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeysResult);
        Map<String, String> expectedKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(privateKeysChunk);
        assertThatKeyMap(resultKeysMap).isEqualTo(expectedKeysMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256PublicKeyBytes_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        //arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        PublicKeyBytes[] publicKeysResult = openCLGridResult.getPublicKeyBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        Map<String, String> resultKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(random256PrivateKeys, publicKeysResult);
        Map<String, String> expectedKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(random256PrivateKeys);
        assertThatKeyMap(resultKeysMap).isEqualTo(expectedKeysMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilPublicKey_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformHexStringToBytes(PRIVATE_KEY_HEX_STRING);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(specificSinglePrivateKey[0]);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilPublicKey_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformPrivateKeyFromBigIntegerToByteArray(randomSinglePrivateKey[0]);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilPublicKey_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromPrivateKeys(random256PrivateKeys, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilPublicKey_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilPublicKey_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_PUBLIC_KEY_ONLY_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilFirstSha_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformHexStringToBytes(PRIVATE_KEY_HEX_STRING);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(specificSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilFirstSha_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformPrivateKeyFromBigIntegerToByteArray(randomSinglePrivateKey[0]);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilFirstSha_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromPrivateKeys(random256PrivateKeys, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilFirstSha_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilFirstSha_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_1ST_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilRipemd_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformHexStringToBytes(PRIVATE_KEY_HEX_STRING);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(specificSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilRipemd_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformPrivateKeyFromBigIntegerToByteArray(randomSinglePrivateKey[0]);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilRipemd_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromPrivateKeys(random256PrivateKeys, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilRipemd_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilRipemd_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_RIPEMD160_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilSecondSha_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformHexStringToBytes(PRIVATE_KEY_HEX_STRING);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(specificSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);
        byte[] expectedRipemd160WithVersionByte = TestHelper.calculateDigestWithVersionByteFromByteArray(expectedRipemd160);
        byte[] expectedSecondSha256 = TestHelper.calculateSha256FromByteArray(expectedRipemd160WithVersionByte);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(result.getSecondSha256Bytes(), is(equalTo(expectedSecondSha256)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilSecondSha_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformPrivateKeyFromBigIntegerToByteArray(randomSinglePrivateKey[0]);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);
        byte[] expectedRipemd160WithVersionByte = TestHelper.calculateDigestWithVersionByteFromByteArray(expectedRipemd160);
        byte[] expectedSecondSha256 = TestHelper.calculateSha256FromByteArray(expectedRipemd160WithVersionByte);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(result.getSecondSha256Bytes(), is(equalTo(expectedSecondSha256)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilSecondSha_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilSecondSha_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilSecondSha_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromPrivateKeys(random256PrivateKeys, OpenCLContext.GEN_UNTIL_2ND_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilThirdSha_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformHexStringToBytes(PRIVATE_KEY_HEX_STRING);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(specificSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);
        byte[] expectedRipemd160WithVersionByte = TestHelper.calculateDigestWithVersionByteFromByteArray(expectedRipemd160);
        byte[] expectedSecondSha256 = TestHelper.calculateSha256FromByteArray(expectedRipemd160WithVersionByte);
        byte[] expectedThirdSha256 = TestHelper.calculateSha256FromByteArray(expectedSecondSha256);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(result.getSecondSha256Bytes(), is(equalTo(expectedSecondSha256)));
        assertThat(result.getThirdSha256Bytes(), is(equalTo(expectedThirdSha256)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilThirdSha_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformPrivateKeyFromBigIntegerToByteArray(randomSinglePrivateKey[0]);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);
        byte[] expectedRipemd160WithVersionByte = TestHelper.calculateDigestWithVersionByteFromByteArray(expectedRipemd160);
        byte[] expectedSecondSha256 = TestHelper.calculateSha256FromByteArray(expectedRipemd160WithVersionByte);
        byte[] expectedThirdSha256 = TestHelper.calculateSha256FromByteArray(expectedSecondSha256);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(result.getSecondSha256Bytes(), is(equalTo(expectedSecondSha256)));
        assertThat(result.getThirdSha256Bytes(), is(equalTo(expectedThirdSha256)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilThirdSha__specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilThirdSha__randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilThirdSha_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromPrivateKeys(random256PrivateKeys, OpenCLContext.GEN_UNTIL_3RD_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilAddress_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_ADDRESS_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformPrivateKeyFromBigIntegerToByteArray(specificSinglePrivateKey[0]);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(specificSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);
        byte[] expectedRipemd160WithVersionByte = TestHelper.calculateDigestWithVersionByteFromByteArray(expectedRipemd160);
        byte[] expectedSecondSha256 = TestHelper.calculateSha256FromByteArray(expectedRipemd160WithVersionByte);
        byte[] expectedThirdSha256 = TestHelper.calculateSha256FromByteArray(expectedSecondSha256);
        byte[] expectedAddress = TestHelper.calculateAddressFromRipemd160(expectedRipemd160);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(result.getSecondSha256Bytes(), is(equalTo(expectedSecondSha256)));
        assertThat(result.getThirdSha256Bytes(), is(equalTo(expectedThirdSha256)));
        assertThat(result.getAddressBytes(), is(equalTo(expectedAddress)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleResultBytes_untilAddress_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_ADDRESS_MODE, SHIFT_NONE);
        byte[] privateKey = TestHelper.transformPrivateKeyFromBigIntegerToByteArray(randomSinglePrivateKey[0]);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedFirstSha256 = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160 = TestHelper.calculateRipemd160FromByteArray(expectedFirstSha256);
        byte[] expectedRipemd160WithVersionByte = TestHelper.calculateDigestWithVersionByteFromByteArray(expectedRipemd160);
        byte[] expectedSecondSha256 = TestHelper.calculateSha256FromByteArray(expectedRipemd160WithVersionByte);
        byte[] expectedThirdSha256 = TestHelper.calculateSha256FromByteArray(expectedSecondSha256);
        byte[] expectedAddress = TestHelper.calculateAddressFromRipemd160(expectedRipemd160);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes result = openCLGridResult.getResultBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThat(result.getPrivateKeyBytes(), is(equalTo(privateKey)));
        assertThat(result.getPublicKeyBytes(), is(equalTo(expectedPublicKey)));
        assertThat(result.getFirstSha256BytesBytes(), is(equalTo(expectedFirstSha256)));
        assertThat(result.getRipemd160BytesBytes(), is(equalTo(expectedRipemd160)));
        assertThat(result.getSecondSha256Bytes(), is(equalTo(expectedSecondSha256)));
        assertThat(result.getThirdSha256Bytes(), is(equalTo(expectedThirdSha256)));
        assertThat(result.getAddressBytes(), is(equalTo(expectedAddress)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilAddress_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_ADDRESS_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_ADDRESS_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilAddress_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_UNTIL_ADDRESS_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromSinglePrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE, OpenCLContext.GEN_UNTIL_ADDRESS_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256ResultBytes_untilAddress_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_UNTIL_ADDRESS_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        ResultBytes[] expected = TestHelper.createExpectedResultBytesFromPrivateKeys(random256PrivateKeys, OpenCLContext.GEN_UNTIL_ADDRESS_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        ResultBytes[] result = openCLGridResult.getResultBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatResultBytesArray(result).isEqualTo(expected);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleAddressBytes_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_ADDRESSES_ONLY_MODE, SHIFT_NONE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        AddressBytes result = openCLGridResult.getAddressBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        String privateKeyResultAsHexString = TestHelper.transformBytesToHexString(result.getPrivateKey());
        String addressResultAsBase58String = TestHelper.transformAddressBytesToBase58String(result.getAddress());
        assertThat(privateKeyResultAsHexString, is(equalTo(PRIVATE_KEY_HEX_STRING)));
        assertThat(addressResultAsBase58String, is(equalTo(ADDRESS_BASE58_STRING)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleAddressBytes_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_ADDRESSES_ONLY_MODE, SHIFT_NONE);
        String expectedPrivateKey = TestHelper.transformBigIntegerToHexString(randomSinglePrivateKey[0]);
        byte[] expectedAddressByteArray = TestHelper.calculateAddressFromPrivateKey(randomSinglePrivateKey[0]);
        String expectedAddress = TestHelper.transformAddressBytesToBase58String(expectedAddressByteArray);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        AddressBytes result = openCLGridResult.getAddressBytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        String privateKeyResultAsHexString = TestHelper.transformBytesToHexString(result.getPrivateKey());
        String addressResultAsBase58String = TestHelper.transformAddressBytesToBase58String(result.getAddress());
        assertThat(privateKeyResultAsHexString, is(equalTo(expectedPrivateKey)));
        assertThat(addressResultAsBase58String, is(equalTo(expectedAddress)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256AddressBytes_specificSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_ADDRESSES_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        AddressBytes[] expectedAddressBytes = TestHelper.createExpectedAddressBytesChunkFromPrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        AddressBytes[] resultedAddressBytes = openCLGridResult.getAddressBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatAddressBytesArray(resultedAddressBytes).isEqualTo(expectedAddressBytes);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256AddressBytes_randomSinglePrivateKey_chunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_ADDRESSES_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        AddressBytes[] expectedAddressBytes = TestHelper.createExpectedAddressBytesChunkFromPrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        AddressBytes[] resultedAddressBytes = openCLGridResult.getAddressBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatAddressBytesArray(resultedAddressBytes).isEqualTo(expectedAddressBytes);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256AddressBytes_random256PrivateKeys_nonChunkMode() throws InvalidWorkSizeException {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_ADDRESSES_ONLY_MODE, SHIFT_8_BITS_FOR_256_CHUNK_SIZE);
        AddressBytes[] expectedAddressBytes = TestHelper.createExpectedAddressBytesFromPrivateKeys(randomSinglePrivateKey);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        AddressBytes[] resultedAddressBytes = openCLGridResult.getAddressBytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        assertThatAddressBytesArray(resultedAddressBytes).isEqualTo(expectedAddressBytes);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }
}