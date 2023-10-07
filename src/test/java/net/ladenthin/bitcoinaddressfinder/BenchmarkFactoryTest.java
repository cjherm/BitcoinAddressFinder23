package net.ladenthin.bitcoinaddressfinder;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactory;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactoryException;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.ChunkSizeIteratorBenchmark;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmark;
import org.junit.Ignore;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

@Ignore
public class BenchmarkFactoryTest {

    @Test
    public void test_createBenchmarkIterator_chunkMode_kernelModeAddress() throws BenchmarkFactoryException {
        // arrange
        CBenchmark configFile = new CBenchmark();
        configFile.type = BenchmarkFactory.TYPE_CHUNK_ITERATOR;
        configFile.chunkMode = true;
        configFile.kernelMode = 2;
        configFile.gridNumBits = 1;
        configFile.totalRounds = 3;
        configFile.contextRounds = 1;
        configFile.logToFile = false;
        configFile.logToConsole = true;
        BenchmarkFactory factory = new BenchmarkFactory(configFile);

        // act
        BenchmarkType runner = factory.createBenchmarkRunner();

        // assert
        assertThat(runner, instanceOf(ChunkSizeIteratorBenchmark.class));
    }
}