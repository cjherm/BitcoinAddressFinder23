package net.ladenthin.bitcoinaddressfinder.benchmark.types;

import net.ladenthin.bitcoinaddressfinder.benchmark.*;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.util.ArrayList;
import java.util.List;

/**
 * Will start a benchmark of a specified numbers of contexts and run every context a specified number of types using
 * the GEN_RIPEMD160_ONLY_MODE kernel mode
 */
public class CtxRoundsIteratorBenchmark implements BenchmarkType {

    public static final String BENCHMARK_NAME = " CTXROUNDS_ITERATOR ";

    private final int gridNumBits;
    private final boolean chunkMode;
    private final int measuringRounds;
    private final int kernelMode;
    private final int maxContextRounds;
    private final BenchmarkLogger logger;

    private List<CProducerOpenCL> producers;
    private List<MeasurementRound> rounds;
    private List<MeasurementRoundResult> measurementRoundResults;

    public CtxRoundsIteratorBenchmark(int gridNumBits, boolean chunkMode, int kernelMode, int maxContextRounds, BenchmarkLogger logger) {
        this.gridNumBits = gridNumBits;
        this.chunkMode = chunkMode;
        this.kernelMode = kernelMode;
        this.measuringRounds = maxContextRounds;
        this.maxContextRounds = maxContextRounds;
        this.logger = logger;
        logger.initLogFile(BENCHMARK_NAME.trim());
    }

    public void start() {
        logger.info("Starting " + BENCHMARK_NAME.trim() + "!");

        createProducers();
        try {
            initializingBenchmarkRounds();
        } catch (BenchmarkException | OutOfMemoryError e) {
            logger.error("Error while trying to initialize \"" + BENCHMARK_NAME.trim() + "\"!");
            logger.error(e.getMessage());
            return;
        }
        measurementRoundResults = new ArrayList<>();

        logger.startBenchmark(BENCHMARK_NAME, kernelMode, gridNumBits, chunkMode, maxContextRounds, measuringRounds);
        int currentRound = 1;

        // Start of benchmark
        long benchmarkStart = System.currentTimeMillis();
        for (MeasurementRound round : rounds) {
            try {
                logger.info("Round " + currentRound + "/" + measuringRounds + ":");
                currentRound++;
                MeasurementRoundResult measurementRoundResult = round.start();
                logger.roundResult(measurementRoundResult);
                measurementRoundResults.add(measurementRoundResult);
            } catch (BenchmarkException e) {
                logger.error("Error when trying to start round " + (currentRound - 1) + "/" + measuringRounds + "!");
                logger.error(e.getInitialThrowable().getMessage());
            } catch (OutOfMemoryError e) {
                logger.error("ChunkSize is too large!");
                logger.error(e.getMessage());
                CtxRoundsIteratorBenchmark reRun = new CtxRoundsIteratorBenchmark((gridNumBits - 1), chunkMode, measuringRounds, maxContextRounds, logger);
                reRun.start();
                return;
            }
        }
        long benchmarkFinish = System.currentTimeMillis();
        // End of benchmark

        logger.logFinalResults(benchmarkStart, benchmarkFinish, measurementRoundResults);
    }

    private void initializingBenchmarkRounds() throws BenchmarkException {
        logger.info("Initializing measuring rounds...");
        rounds = new ArrayList<>();
        int contextRounds = 1;
        for (CProducerOpenCL producer : producers) {
            String parameterToPrint = "2^{" + producer.gridNumBits + "} = " + (1 << producer.gridNumBits) + ", " + contextRounds + "x/ctx, cm:" + chunkMode;
            rounds.add(BenchmarkFactory.createBenchmarkRound(producer, contextRounds, contextRounds + "", parameterToPrint, logger));
            contextRounds++;
        }
        logger.info(rounds.size() + " measuring rounds successfully initialized!");
    }

    private void createProducers() {
        logger.info("Creating CProducerOpenCL configurations...");
        producers = new ArrayList<>();
        for (int i = 0; i < maxContextRounds; i++) {
            CProducerOpenCL producerOpenCL = new CProducerOpenCL();
            producerOpenCL.gridNumBits = gridNumBits;
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