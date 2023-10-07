package net.ladenthin.bitcoinaddressfinder;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactory;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactoryException;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.ChunkSizeIteratorBenchmark;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.CtxRoundsIteratorBenchmark;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.DefaultBenchmark;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmark;
import org.junit.Ignore;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

@Ignore
public class BenchmarkFactoryTest {

    @Test
    public void test_createBenchmarkChunkSizeIterator() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = BenchmarkFactory.DEFAULT_KERNELMODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);

        // act
        BenchmarkType runner = factory.createBenchmarkRunner();

        // assert
        assertThat(runner, instanceOf(ChunkSizeIteratorBenchmark.class));
    }

    @Test
    public void test_createBenchmarkCtxRoundsIterator() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CTX_ITERATOR;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = BenchmarkFactory.DEFAULT_KERNELMODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);

        // act
        BenchmarkType runner = factory.createBenchmarkRunner();

        // assert
        assertThat(runner, instanceOf(CtxRoundsIteratorBenchmark.class));
    }

    @Test
    public void test_createBenchmarkDefault() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_DEFAULT;
        configFile.chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;
        configFile.kernelMode = BenchmarkFactory.DEFAULT_KERNELMODE;
        configFile.gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;
        configFile.totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;
        configFile.contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;
        configFile.logToFile = false;
        configFile.logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);

        // act
        BenchmarkType runner = factory.createBenchmarkRunner();

        // assert
        assertThat(runner, instanceOf(DefaultBenchmark.class));
    }
}