package net.ladenthin.bitcoinaddressfinder.benchmark.types;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;

/**
 * Will start a benchmark of a specified numbers of contexts and run every context a specified number of types using
 * the GEN_RIPEMD160_ONLY_MODE kernel mode
 */
public class DefaultBenchmark implements BenchmarkType {

    private final int gridNumBits;
    private final boolean chunkMode;
    private final int measuringRounds;
    private final int roundsPerInitializedContext;
    private final BenchmarkLogger logger;

    public DefaultBenchmark(int gridNumBits, boolean chunkMode, int measuringRounds, int roundsPerInitializedContext, BenchmarkLogger logger) {
        this.gridNumBits = gridNumBits;
        this.chunkMode = chunkMode;
        this.measuringRounds = measuringRounds;
        this.roundsPerInitializedContext = roundsPerInitializedContext;
        this.logger = logger;
    }

    @Override
    public void start() {

    }

    @Override
    public int getTotalNumberOfResults() {
        return 0;
    }

    @Override
    public String getName() {
        return null;
    }
}