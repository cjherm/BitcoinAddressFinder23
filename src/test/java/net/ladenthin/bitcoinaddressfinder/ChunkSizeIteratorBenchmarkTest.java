package net.ladenthin.bitcoinaddressfinder;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactory;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactoryException;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmark;
import org.junit.Ignore;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Ignore
public class ChunkSizeIteratorBenchmarkTest {

    public static final int EXPECTED_RESULTS_UNTIL_GNB_1 = 3;
    public static final int EXPECTED_RESULTS_UNTIL_GNB_8 = 5110;

    @Test
    public void test_start_untilGridNumBits1_3totalResults() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.gridNumBits = 1;
        configFile.chunkMode = true;
        configFile.kernelMode = OpenCLContext.GEN_RIPEMD160_ONLY_MODE;
        configFile.contextRounds = 1;
        configFile.logToConsole = true;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_GNB_1));
    }

    @Test
    public void test_start_chunkSizeIterator_chunkMode_ripemd160() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = true;
        configFile.kernelMode = OpenCLContext.GEN_RIPEMD160_ONLY_MODE;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = true;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_GNB_8));
    }

    @Test
    public void test_start_chunkSizeIterator_chunkMode_publicKeyBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.chunkMode = true;
        configFile.kernelMode = OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = true;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_GNB_8));
    }

    @Test
    public void test_start_chunkSizeIterator_chunkMode_addressBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = OpenCLContext.GEN_ADDRESSES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = true;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_GNB_8));
    }

    @Test
    public void test_start_chunkSizeIterator_nonChunkMode_publicKeyBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = true;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_GNB_8));
    }

    @Test
    public void test_start_chunkSizeIterator_nonChunkMode_ripemd160() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_RIPEMD160_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = true;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_GNB_8));
    }

    @Test
    public void test_start_chunkSizeIterator_nonChunkMode_addressBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_ADDRESSES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = true;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_GNB_8));
    }
}