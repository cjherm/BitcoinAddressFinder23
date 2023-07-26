package net.ladenthin.bitcoinaddressfinder;

import org.jocl.CL;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Map;

import static net.ladenthin.bitcoinaddressfinder.TestHelper.assertThatKeyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

/**
 * Tests the publicKey and address calculation of an OpenClContext without considering the performance.
 */
public class OpenCLContextTest {

    public static final int CHUNK_SIZE = 256;

    private static final boolean CHUNK_MODE = true;
    private static final boolean NON_CHUNK_MODE = false;
    private static final String PRIVATE_KEY_HEX_STRING = "C297E4944F46F3B9F04CF4B3984F49BD4EE40DEC33991066FA15CDB227933400";
    private static final String PUBLIC_KEY_HEX_STRING = "04ccc8a095355a8479d9ef89eb6e435fb7fd9b2120dba38f71bf51a51f2fe66d6f64e30ee36de0a5691ad6d8036919ce8dc3ffb073510b8535675e103c045c6f44";
    private static final String SINGLE_SHA256_FROM_PUBLIC_KEY_HEX_STRING = "7ae93296d94ad53c2fb50a0f65e41437335e30fa6cef67b9e4aa2886feba5d40";
    private static final String DOUBLE_SHA256_FROM_PUBLIC_KEY_HEX_STRING = "e2f1cadac9b0458532cc50eee4787bf30809d827bbf0170ef0c6e2a8459199b7";
    private static final String ERROR_CODE_SUCCESS = CL.stringFor_errorCode(CL.CL_SUCCESS);

    @Test
    public void test_generateSinglePublicKey_specificSinglePrivateKey() {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEYS_MODE);

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
    public void test_generateSinglePublicKey_randomSinglePrivateKey() {
        //arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEYS_MODE);

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
    public void test_generate256PublicKeys_specificSinglePrivateKey_chunkMode() {
        //arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEYS_MODE);

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
    public void test_generate256PublicKeys_randomSinglePrivateKey_chunkMode() {
        //arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEYS_MODE);

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
    public void test_generate256PublicKeys_random256PrivateKeys_nonChunkMode() {
        //arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_PUBLIC_KEYS_MODE);

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
    public void test_generateSingleSha256Hash_specificSinglePrivateKey() {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);
        byte[] expectedSha256ByteArray = TestHelper.transformHexStringToBytes(SINGLE_SHA256_FROM_PUBLIC_KEY_HEX_STRING);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes publicKeyBytesResult = openCLGridResult.getPublicKeyBytes()[0];
        Sha256Bytes sha256BytesResult = openCLGridResult.getSha256Bytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        byte[] sha256HashResult = sha256BytesResult.getFirstSha256Bytes();
        assertThat(publicKeyBytesResult.getUncompressed(), is(equalTo(TestHelper.transformHexStringToBytes(PUBLIC_KEY_HEX_STRING))));
        assertThat(sha256HashResult, is(equalTo(expectedSha256ByteArray)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateSingleSha256Hash_randomSinglePrivateKey() {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedSha256Hash = TestHelper.calculateSha256FromByteArray(expectedPublicKey);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes publicKeyBytesResult = openCLGridResult.getPublicKeyBytes()[0];
        Sha256Bytes sha256BytesResult = openCLGridResult.getSha256Bytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        byte[] sha256HashResult = sha256BytesResult.getFirstSha256Bytes();
        assertThat(publicKeyBytesResult.getUncompressed(), is(equalTo(expectedPublicKey)));
        assertThat(sha256HashResult, is(equalTo(expectedSha256Hash)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256SingleSha256Hashes_random256PrivateKeys_nonChunkMode() {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(random256PrivateKeys, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(random256PrivateKeys);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256SingleSha256Hashes_specificSinglePrivateKey_chunkMode() {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(privateKeysChunk);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256SingleSha256Hashes_randomSinglePrivateKey_chunkMode() {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(privateKeysChunk);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateDoubleSha256Hash_specificSinglePrivateKey() {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);
        byte[] expectedSingleHashedSha256ByteArray = TestHelper.transformHexStringToBytes(SINGLE_SHA256_FROM_PUBLIC_KEY_HEX_STRING);
        byte[] expectedDoubleHashedSha256ByteArray = TestHelper.transformHexStringToBytes(DOUBLE_SHA256_FROM_PUBLIC_KEY_HEX_STRING);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes publicKeyBytesResult = openCLGridResult.getPublicKeyBytes()[0];
        Sha256Bytes sha256BytesResult = openCLGridResult.getSha256Bytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        byte[] firstSha256HashResult = sha256BytesResult.getFirstSha256Bytes();
        byte[] secondSha256HashResult = sha256BytesResult.getSecondSha256Bytes();
        assertThat(publicKeyBytesResult.getUncompressed(), is(equalTo(TestHelper.transformHexStringToBytes(PUBLIC_KEY_HEX_STRING))));
        assertThat(firstSha256HashResult, is(equalTo(expectedSingleHashedSha256ByteArray)));
        assertThat(secondSha256HashResult, is(equalTo(expectedDoubleHashedSha256ByteArray)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateDoubleSha256Hash_randomSinglePrivateKey() {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedSingleHashedSha256ByteArray = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedDoubleHashedSha256ByteArray = TestHelper.calculateSha256FromByteArray(expectedSingleHashedSha256ByteArray);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes publicKeyBytesResult = openCLGridResult.getPublicKeyBytes()[0];
        Sha256Bytes sha256BytesResult = openCLGridResult.getSha256Bytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // assert
        byte[] firstSha256HashResult = sha256BytesResult.getFirstSha256Bytes();
        byte[] secondSha256HashResult = sha256BytesResult.getSecondSha256Bytes();
        assertThat(publicKeyBytesResult.getUncompressed(), is(equalTo(expectedPublicKey)));
        assertThat(firstSha256HashResult, is(equalTo(expectedSingleHashedSha256ByteArray)));
        assertThat(secondSha256HashResult, is(equalTo(expectedDoubleHashedSha256ByteArray)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256DoubleSha256Hashes_specificSinglePrivateKeys_chunkMode() {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(privateKeysChunk);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        Map<String, String> resultedDoubleSha256HashesMap = TestHelper.createResultedMapOfSha256HashesAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedDoubleSha256HashesMap = TestHelper.createExpectedMapOfSha256HashesToSha256Hases(sha256BytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThatKeyMap(resultedDoubleSha256HashesMap).isEqualTo(expectedDoubleSha256HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256DoubleSha256Hashes_randomSinglePrivateKeys_chunkMode() {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(privateKeysChunk);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        Map<String, String> resultedDoubleSha256HashesMap = TestHelper.createResultedMapOfSha256HashesAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedDoubleSha256HashesMap = TestHelper.createExpectedMapOfSha256HashesToSha256Hases(sha256BytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThatKeyMap(resultedDoubleSha256HashesMap).isEqualTo(expectedDoubleSha256HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256DoubleSha256Hashes_random256PrivateKeys_nonChunkMode() {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_SHA256_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(random256PrivateKeys, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(random256PrivateKeys);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        Map<String, String> resultedDoubleSha256HashesMap = TestHelper.createResultedMapOfSha256HashesAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedDoubleSha256HashesMap = TestHelper.createExpectedMapOfSha256HashesToSha256Hases(sha256BytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThatKeyMap(resultedDoubleSha256HashesMap).isEqualTo(expectedDoubleSha256HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateRipemd160Hash_specificSinglePrivateKey() {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_RIPEMD160_MODE);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(specificSinglePrivateKey[0]);
        byte[] expectedSha256Hash = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160Hash = TestHelper.calculateRipemd160FromByteArray(expectedSha256Hash);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes publicKeyBytesResult = openCLGridResult.getPublicKeyBytes()[0];
        Ripemd160Bytes ripemd160BytesResult = openCLGridResult.getRipemd160Bytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        byte[] firstSha256HashResult = ripemd160BytesResult.getSha256Bytes();
        byte[] ripemd160HashResult = ripemd160BytesResult.getRipemd160Bytes();

        // assert
        assertThat(publicKeyBytesResult.getUncompressed(), is(equalTo(expectedPublicKey)));
        assertThat(firstSha256HashResult, is(equalTo(expectedSha256Hash)));
        assertThat(ripemd160HashResult, is(equalTo(expectedRipemd160Hash)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generateRipemd160Hash_randomSinglePrivateKey() {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_RIPEMD160_MODE);
        byte[] expectedPublicKey = TestHelper.calculatePublicKeyAsBytesFromPrivateKey(randomSinglePrivateKey[0]);
        byte[] expectedSha256Hash = TestHelper.calculateSha256FromByteArray(expectedPublicKey);
        byte[] expectedRipemd160Hash = TestHelper.calculateRipemd160FromByteArray(expectedSha256Hash);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes publicKeyBytesResult = openCLGridResult.getPublicKeyBytes()[0];
        Ripemd160Bytes ripemd160BytesResult = openCLGridResult.getRipemd160Bytes()[0];

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        byte[] sha256BytesResult = ripemd160BytesResult.getSha256Bytes();
        byte[] ripemd160HashResult = ripemd160BytesResult.getRipemd160Bytes();

        // assert
        assertThat(publicKeyBytesResult.getUncompressed(), is(equalTo(expectedPublicKey)));
        assertThat(sha256BytesResult, is(equalTo(expectedSha256Hash)));
        assertThat(ripemd160HashResult, is(equalTo(expectedRipemd160Hash)));
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256Ripemd160Hashes_specificSinglePrivateKey_chunkMode() {
        // arrange
        BigInteger[] specificSinglePrivateKey = TestHelper.transformHexStringToBigIntegerArray(PRIVATE_KEY_HEX_STRING);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_RIPEMD160_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(specificSinglePrivateKey);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();
        Ripemd160Bytes[] ripemd160BytesResult = openCLGridResult.getRipemd160Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(specificSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(privateKeysChunk);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        Map<String, String> resultedSha256HashesRipemd160HashesMap = TestHelper.createResultedMapOfSha256HashesAndTheirRipemd160Hashes(ripemd160BytesResult);
        Map<String, String> expectedSha256HashesRipemd160HashesMap = TestHelper.createExpectedMapOfSha256HashesToRipemd160Hashes(sha256BytesResult);

        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThatKeyMap(resultedSha256HashesRipemd160HashesMap).isEqualTo(expectedSha256HashesRipemd160HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256Ripemd160Hashes_randomSinglePrivateKey_chunkMode() {
        // arrange
        BigInteger[] randomSinglePrivateKey = TestHelper.generateRandomPrivateKeys(1);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(CHUNK_MODE, OpenCLContext.GEN_RIPEMD160_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(randomSinglePrivateKey);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();
        Ripemd160Bytes[] ripemd160BytesResult = openCLGridResult.getRipemd160Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        BigInteger[] privateKeysChunk = TestHelper.calculatePrivateKeyChunkFromSinglePrivateKey(randomSinglePrivateKey[0], CHUNK_SIZE);
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(privateKeysChunk, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(privateKeysChunk);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        Map<String, String> resultedSha256HashesRipemd160HashesMap = TestHelper.createResultedMapOfSha256HashesAndTheirRipemd160Hashes(ripemd160BytesResult);
        Map<String, String> expectedSha256HashesRipemd160HashesMap = TestHelper.createExpectedMapOfSha256HashesToRipemd160Hashes(sha256BytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThatKeyMap(resultedSha256HashesRipemd160HashesMap).isEqualTo(expectedSha256HashesRipemd160HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }

    @Test
    public void test_generate256Ripemd160Hashes_randomSinglePrivateKey_nonChunkMode() {
        // arrange
        BigInteger[] random256PrivateKeys = TestHelper.generateRandomPrivateKeys(CHUNK_SIZE);
        OpenCLContext openCLContext = TestHelper.createOpenCLContext(NON_CHUNK_MODE, OpenCLContext.GEN_RIPEMD160_MODE);

        // act
        OpenCLGridResult openCLGridResult = openCLContext.createResult(random256PrivateKeys);
        PublicKeyBytes[] publicKeyBytesResult = openCLGridResult.getPublicKeyBytes();
        Sha256Bytes[] sha256BytesResult = openCLGridResult.getSha256Bytes();
        Ripemd160Bytes[] ripemd160BytesResult = openCLGridResult.getRipemd160Bytes();

        // cleanup
        openCLContext.release();
        openCLGridResult.freeResult();

        // prepare assert
        Map<String, String> resultedPrivateKeysPublicKeysMap = TestHelper.createResultedMapOfPrivateKeysAndTheirPublicKeys(random256PrivateKeys, publicKeyBytesResult);
        Map<String, String> expectedPrivateKeysPublicKeysMap = TestHelper.createExpectedMapOfPrivateKeysToPublicKeys(random256PrivateKeys);

        Map<String, String> resultedPublicKeysSha256HashesMap = TestHelper.createResultedMapOfPublicKeysAndTheirSha256Hashes(sha256BytesResult);
        Map<String, String> expectedPublicKeysSha256HashesMap = TestHelper.createExpectedMapOfPublicKeysToSha256Hashes(publicKeyBytesResult);

        Map<String, String> resultedSha256HashesRipemd160HashesMap = TestHelper.createResultedMapOfSha256HashesAndTheirRipemd160Hashes(ripemd160BytesResult);
        Map<String, String> expectedSha256HashesRipemd160HashesMap = TestHelper.createExpectedMapOfSha256HashesToRipemd160Hashes(sha256BytesResult);

        // assert
        assertThatKeyMap(resultedPrivateKeysPublicKeysMap).isEqualTo(expectedPrivateKeysPublicKeysMap);
        assertThatKeyMap(resultedPublicKeysSha256HashesMap).isEqualTo(expectedPublicKeysSha256HashesMap);
        assertThatKeyMap(resultedSha256HashesRipemd160HashesMap).isEqualTo(expectedSha256HashesRipemd160HashesMap);
        assertThat(openCLContext.getErrorCodeString(), is(equalTo(ERROR_CODE_SUCCESS)));
    }
}