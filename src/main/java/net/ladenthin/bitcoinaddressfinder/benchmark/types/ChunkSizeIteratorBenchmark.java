package net.ladenthin.bitcoinaddressfinder.benchmark.types;

import net.ladenthin.bitcoinaddressfinder.benchmark.*;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.util.ArrayList;
import java.util.List;

/**
 * Will start a benchmark run with chunkSize 2^0=1 and increase it until target size is reached.
 */
public class ChunkSizeIteratorBenchmark implements BenchmarkType {

    public static final String BENCHMARK_NAME = " CHUNKSIZE_ITERATOR ";

    private final int gridNumBitsMaxSize;
    private final boolean chunkMode;
    private final int kernelMode;
    private final int roundsPerInitializedContext;
    private final BenchmarkLogger logger;

    private List<CProducerOpenCL> producers;
    private List<MeasurementRound> rounds;
    private List<MeasurementRoundResult> measurementRoundResults;
    private int numberOfIterations;

    public ChunkSizeIteratorBenchmark(int gridNumBitsMaxSize, boolean chunkMode, int kernelMode, int roundsPerInitializedContext, BenchmarkLogger logger) {
        this.gridNumBitsMaxSize = gridNumBitsMaxSize;
        this.chunkMode = chunkMode;
        this.kernelMode = kernelMode;
        this.roundsPerInitializedContext = roundsPerInitializedContext;
        this.logger = logger;
        logger.initLogFile(BENCHMARK_NAME.trim());
    }

    public void start() {
        logger.info("Starting " + BENCHMARK_NAME.trim() + "!");

        // including 2 << 0 as first iteration
        numberOfIterations = gridNumBitsMaxSize + 1;

        createProducers();
        try {
            initializingBenchmarkRounds();
        } catch (BenchmarkException | OutOfMemoryError e) {
            logger.error("Error while trying to initialize \"" + BENCHMARK_NAME.trim() + "\"!");
            logger.error(e.getMessage());
            return;
        }
        measurementRoundResults = new ArrayList<>();

        logger.startBenchmark(BENCHMARK_NAME, kernelMode, gridNumBitsMaxSize, chunkMode, roundsPerInitializedContext, numberOfIterations);
        int currentRound = 1;

        // Start of benchmark
        long benchmarkStart = System.currentTimeMillis();
        for (MeasurementRound round : rounds) {
            try {
                logger.info("Round " + currentRound + "/" + numberOfIterations + ":");
                currentRound++;
                MeasurementRoundResult measurementRoundResult = round.start();
                logger.roundResult(measurementRoundResult);
                measurementRoundResults.add(measurementRoundResult);
            } catch (BenchmarkException e) {
                logger.error("Error when trying to start round " + (currentRound - 1) + "/" + numberOfIterations + "!");
                logger.error(e.getInitialThrowable().getMessage());
            } catch (OutOfMemoryError e) {
                logger.error("ChunkSize is too large!");
                logger.error(e.getMessage());
                break;
            }
        }
        long benchmarkFinish = System.currentTimeMillis();
        // End of benchmark

        logger.logFinalResults(benchmarkStart, benchmarkFinish, measurementRoundResults);
    }

    private void initializingBenchmarkRounds() throws BenchmarkException {
        logger.info("Initializing measuring rounds...");
        rounds = new ArrayList<>();
        for (CProducerOpenCL producer : producers) {
            String parameterToLatex = "2^{" + producer.gridNumBits + "}";
            String parameterToPrint = parameterToLatex + " = " + (1 << producer.gridNumBits) + ", " + roundsPerInitializedContext + "x/ctx, cm:" + chunkMode;
            rounds.add(BenchmarkFactory.createBenchmarkRound(producer, roundsPerInitializedContext, "$" + parameterToLatex + "$", parameterToPrint, logger));
        }
        logger.info(rounds.size() + " measuring rounds successfully initialized!");
    }

    private void createProducers() {
        logger.info("Creating configurations...");
        producers = new ArrayList<>();
        for (int i = 0; i < numberOfIterations; i++) {
            CProducerOpenCL producerOpenCL = new CProducerOpenCL();
            producerOpenCL.gridNumBits = i;
            producerOpenCL.chunkMode = chunkMode;
            producerOpenCL.kernelMode = kernelMode;
            producers.add(producerOpenCL);
        }
        logger.info("Configurations successfully created!");
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