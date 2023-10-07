package net.ladenthin.bitcoinaddressfinder.benchmark;

import java.util.List;

public class BenchmarkLogger {

    public BenchmarkLogger(boolean logToConsole, boolean logToFile) {
        // TODO impl
    }

    public static void staticInfo(String s) {
        // TODO impl
    }

    public static void staticError(String msg) {
        // TODO impl
    }

    public void warn(String s) {
        // TODO impl
    }

    public void error(String msg) {
        // TODO impl
    }

    public void initLogFile(String trim) {
        // TODO impl
    }

    public void info(String s) {
        // TODO impl
    }

    public void startBenchmark(String benchmarkName, int kernelMode, int gridNumBitsMaxSize, boolean chunkMode, int roundsPerInitializedContext, int numberOfIterations) {
        // TODO impl
    }

    public void roundResult(MeasurementRoundResult measurementRoundResult) {
        // TODO impl
    }

    public void logFinalResults(long benchmarkStart, long benchmarkFinish, List<MeasurementRoundResult> measurementRoundResults) {
        // TODO impl
    }
}