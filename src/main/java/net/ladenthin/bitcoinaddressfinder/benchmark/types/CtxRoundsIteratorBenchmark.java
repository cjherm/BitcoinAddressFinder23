package net.ladenthin.bitcoinaddressfinder.benchmark.types;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;

public class CtxRoundsIteratorBenchmark implements BenchmarkType {

    private final int gridNumBits;
    private final boolean chunkMode;
    private final int measuringRounds;
    private final int kernelMode;
    private final int maxContextRounds;
    private final BenchmarkLogger logger;

    public CtxRoundsIteratorBenchmark(int gridNumBits, boolean chunkMode, int kernelMode, int maxContextRounds, BenchmarkLogger logger) {
        this.gridNumBits = gridNumBits;
        this.chunkMode = chunkMode;
        this.kernelMode = kernelMode;
        this.measuringRounds = maxContextRounds;
        this.maxContextRounds = maxContextRounds;
        this.logger = logger;
    }

    @Override
    public void start() {
        // TODO impl
    }

    @Override
    public int getTotalNumberOfResults() {
        // TODO impl
        return 0;
    }

    @Override
    public String getName() {
        // TODO impl
        return null;
    }
}