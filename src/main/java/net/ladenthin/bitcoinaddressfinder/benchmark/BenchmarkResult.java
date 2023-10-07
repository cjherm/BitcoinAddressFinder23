package net.ladenthin.bitcoinaddressfinder.benchmark;

import java.util.ArrayList;
import java.util.List;

public class BenchmarkResult {

    private final List<MeasurementRoundResult> roundResults;
    private final double totalBenchmarkDuration;

    public BenchmarkResult(long benchmarkStart, long benchmarkFinish, List<MeasurementRoundResult> roundResults) {
        this.roundResults = roundResults;
        this.totalBenchmarkDuration = ((double) benchmarkFinish - (double) benchmarkStart) / 1000;
    }

    public List<String> getFinalPrintOut() {
        int totalResults = 0;
        double totalCalcDuration = 0.0;
        for (MeasurementRoundResult singleRoundResult : roundResults) {
            totalResults += singleRoundResult.getNumberOfResults();
            totalCalcDuration += singleRoundResult.getRoundDurationInSeconds();
        }
        int avgResultsPerSecond = (int) (totalResults / totalCalcDuration);
        List<String> printOut = new ArrayList<>();
        printOut.add("Benchmark rounds finished!");
        printOut.add("----------------------------------------------------------------------------------------------------");
        printOut.add("TOTAL NUMBER OF RESULTS: " + totalResults + ", TOTAL DURATION (only calculation): " + totalCalcDuration + "s,");
        printOut.add("RESULTS PER SECOND: " + avgResultsPerSecond + ", TOTAL DURATION (complete): " + totalBenchmarkDuration + "s");
        printOut.add("----------------------------------------------------------------------------------------------------");
        return printOut;
    }
}