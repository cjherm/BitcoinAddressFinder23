package net.ladenthin.bitcoinaddressfinder.benchmark.types;

import net.ladenthin.bitcoinaddressfinder.OpenCLContext;
import net.ladenthin.bitcoinaddressfinder.benchmark.*;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.util.ArrayList;
import java.util.List;

/**
 * Will start a benchmark of a specified numbers of contexts and run every context a specified number of types using
 * the GEN_RIPEMD160_ONLY_MODE kernel mode
 */
public class DefaultBenchmark implements BenchmarkType {

    public static final String BENCHMARK_NAME = "  RIPEMD160_RUNNER  ";

    private final int gridNumBits;
    private final boolean chunkMode;
    private final int measuringRounds;
    private final int roundsPerInitializedContext;
    private final BenchmarkLogger logger;

    private List<MeasurementRoundResult> measurementRoundResults;

    public DefaultBenchmark(int gridNumBits, boolean chunkMode, int measuringRounds, int roundsPerInitializedContext, BenchmarkLogger logger) {
        this.gridNumBits = gridNumBits;
        this.chunkMode = chunkMode;
        this.measuringRounds = measuringRounds;
        this.roundsPerInitializedContext = roundsPerInitializedContext;
        this.logger = logger;
        logger.initLogFile(BENCHMARK_NAME.trim());
    }

    public void start() {
        logger.info("Initializing " + BENCHMARK_NAME.trim() + "!");

        List<MeasurementRound> rounds;
        int kernelMode = OpenCLContext.GEN_RIPEMD160_ONLY_MODE;
        try {
            List<CProducerOpenCL> producers = BenchmarkFactory.createProducers(gridNumBits, chunkMode, kernelMode, measuringRounds, logger);
            rounds = BenchmarkFactory.initializingBenchmarkRounds(gridNumBits, chunkMode, roundsPerInitializedContext, producers, logger);
        } catch (OutOfMemoryError e) {
            logger.error("Error while trying to initialize \"" + BENCHMARK_NAME.trim() + "\"!");
            logger.error(e.getMessage());
            return;
        }
        measurementRoundResults = new ArrayList<>();

        logger.startBenchmark(BENCHMARK_NAME, kernelMode, gridNumBits, chunkMode, roundsPerInitializedContext, measuringRounds);
        int currentRound = 1;

        // Start of benchmark
        long benchmarkStart = System.currentTimeMillis();
        for (MeasurementRound round : rounds) {
            try {
                logger.info("Round " + currentRound + "/" + measuringRounds + ":");
                MeasurementRoundResult measurementRoundResult = round.start();
                logger.roundResult(measurementRoundResult);
                measurementRoundResults.add(measurementRoundResult);
                currentRound++;
            } catch (BenchmarkException e) {
                logger.error("Error when trying to start round " + (currentRound - 1) + "/" + measuringRounds + "!");
                logger.error(e.getInitialThrowable().getMessage());
            } catch (OutOfMemoryError e) {
                logger.error("ChunkSize is too large!");
                logger.error(e.getMessage());
                rounds.clear();
                measurementRoundResults.clear();
                DefaultBenchmark reRun = new DefaultBenchmark((gridNumBits - 1), chunkMode, measuringRounds, roundsPerInitializedContext, logger);
                reRun.start();
                return;
            }
        }
        long benchmarkFinish = System.currentTimeMillis();
        // End of benchmark

        logger.logFinalResults(benchmarkStart, benchmarkFinish, measurementRoundResults);
    }

    @Override
    public int getTotalNumberOfResults() {
        int totalNumberOfResults = 0;
        for (MeasurementRoundResult singleResult : measurementRoundResults) {
            totalNumberOfResults += singleResult.getNumberOfResults();
        }
        return totalNumberOfResults;
    }

    @Override
    public String getName() {
        return BENCHMARK_NAME;
    }
}