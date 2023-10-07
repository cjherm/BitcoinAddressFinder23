package net.ladenthin.bitcoinaddressfinder;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactory;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactoryException;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmark;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class DefaultBenchmarkTest {

    public static final int EXPECTED_RESULTS = (1 << BenchmarkFactory.DEFAULT_GRIDNUMBITS) * BenchmarkFactory.DEFAULT_TOTAL_ROUNDS * BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;

    @Test
    public void test_start_chunkMode_kernelMode2_10xCtx_10xtotalRounds() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_DEFAULT;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = BenchmarkFactory.DEFAULT_KERNELMODE;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS));
    }

    @Test
    public void test_start_chunkMode_kernelMode0_10xCtx_10xtotalRounds() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_DEFAULT;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS));
    }

    @Test
    public void test_start_chunkMode_kernelMode3_10xCtx_10xtotalRounds() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_DEFAULT;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = OpenCLContext.GEN_ADDRESSES_ONLY_MODE;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS));
    }

    @Test
    public void test_start_nonChunkMode_kernelMode2_10xCtx_10xtotalRounds() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_DEFAULT;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = false;
        configFile.kernelMode = BenchmarkFactory.DEFAULT_KERNELMODE;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS));
    }

    @Test
    public void test_start_nonChunkMode_kernelMode0_10xCtx_10xtotalRounds() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_DEFAULT;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS));
    }

    @Test
    public void test_start_nonCunkMode_kernelMode3_10xCtx_10xtotalRounds() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_DEFAULT;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.chunkMode = false;
        configFile.kernelMode = OpenCLContext.GEN_ADDRESSES_ONLY_MODE;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        configFile.logToFile = false;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);
        BenchmarkType runner = factory.createBenchmarkRunner();

        // act
        runner.start();

        // assert
        assertThat(runner.getTotalNumberOfResults(), equalTo(EXPECTED_RESULTS));
    }
}