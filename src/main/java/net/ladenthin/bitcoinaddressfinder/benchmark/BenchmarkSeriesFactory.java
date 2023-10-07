package net.ladenthin.bitcoinaddressfinder.benchmark;

import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmark;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmarkSeries;

import java.util.ArrayList;
import java.util.List;

public class BenchmarkSeriesFactory {

    private final List<CBenchmark> benchmarks;

    private final BenchmarkLogger logger;

    public BenchmarkSeriesFactory(CBenchmarkSeries configuration) {
        BenchmarkFactory.assumeOpenClWorking();
        this.benchmarks = configuration.benchmarks;
        boolean logToConsole = configuration.logToConsole;
        boolean logToFile = configuration.logToFile;
        logger = new BenchmarkLogger(logToConsole, logToFile, BenchmarkSeries.BENCHMARK_NAME.trim());
    }

    public BenchmarkSeries createBenchmarkSeries() throws BenchmarkFactoryException {
        List<BenchmarkType> runners = new ArrayList<>();
        for (CBenchmark config : benchmarks) {
            BenchmarkFactory factory = new BenchmarkFactory(config, logger);
            try {
                runners.add(factory.createBenchmarkRunner());
            } catch (BenchmarkFactoryException e) {
                logger.error("Could not create Benchmark \"" + config.type + "\"");
            }
        }
        if (runners.size() == 0) {
            throw new BenchmarkFactoryException("Could not create any Benchmark!");
        } else {
            logger.info("Created " + runners.size() + " benchmarks!");
        }
        return new BenchmarkSeries(runners, logger);
    }
}