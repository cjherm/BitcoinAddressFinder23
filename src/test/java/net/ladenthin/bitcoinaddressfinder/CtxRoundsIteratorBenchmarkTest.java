package net.ladenthin.bitcoinaddressfinder;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactory;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactoryException;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmark;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class CtxRoundsIteratorBenchmarkTest {

    public static final int EXPECTED_RESULTS_UNTIL_CTX_1 = 1 << BenchmarkFactory.DEFAULT_GRIDNUMBITS;
    public static final int EXPECTED_RESULTS_UNTIL_CTX_10 = 55 * EXPECTED_RESULTS_UNTIL_CTX_1;

    @Test
    public void test_start_untilCtxRound1_256Results() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = OpenCLContext.GEN_RIPEMD160_ONLY_MODE;
        configFile.contextRounds = 1;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_CTX_1));
    }

    @Test
    public void test_start_chunkSizeIterator_chunkMode_ripemd160() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = true;
        configFile.kernelMode = OpenCLContext.GEN_RIPEMD160_ONLY_MODE;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_CTX_10));
    }

    @Test
    public void test_start_chunkSizeIterator_chunkMode_publicKeyBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.chunkMode = true;
        configFile.kernelMode = OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_CTX_10));
    }

    @Test
    public void test_start_chunkSizeIterator_chunkMode_addressBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = OpenCLContext.GEN_ADDRESSES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_CTX_10));
    }

    @Test
    public void test_start_chunkSizeIterator_nonChunkMode_publicKeyBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_CTX_10));
    }

    @Test
    public void test_start_chunkSizeIterator_nonChunkMode_ripemd160() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_RIPEMD160_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_CTX_10));
    }

    @Test
    public void test_start_chunkSizeIterator_nonChunkMode_addressBytes() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_ADDRESSES_ONLY_MODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS_UNTIL_CTX_10));
    }
}