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
}