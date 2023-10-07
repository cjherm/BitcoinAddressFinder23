package net.ladenthin.bitcoinaddressfinder.benchmark;

import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;

import java.util.List;

public class BenchmarkSeries implements BenchmarkType {

    public static final String BENCHMARK_NAME = "BENCHMARK_SERIES";
    private final List<BenchmarkType> runners;
    private final BenchmarkLogger logger;

    public BenchmarkSeries(List<BenchmarkType> runners, BenchmarkLogger logger) {
        this.runners = runners;
        this.logger = logger;
    }

    public void start() {
        logger.info("Starting series of " + runners.size() + " benchmarks...");
        logger.info("///////////////////////////////////////// " + BENCHMARK_NAME + " /////////////////////////////////////////");
        int count = 1;
        for (BenchmarkType runner : runners) {
            logger.info("Starting benchmark " + count + "/" + runners.size() + ":");
            runner.start();
            count++;
        }
        logger.info("///////////////////////////////////////////// THE END! /////////////////////////////////////////////");
        logger.info("FINISHED SERIES OF BENCHMARKS!");
        logger.flush();
    }

    @Override
    public int getTotalNumberOfResults() {
        int totalNumberOfResults = 0;
        for (BenchmarkType benchmark : runners) {
            totalNumberOfResults += benchmark.getTotalNumberOfResults();
        }
        return totalNumberOfResults;
    }

    @Override
    public String getName() {
        return BENCHMARK_NAME;
    }
}