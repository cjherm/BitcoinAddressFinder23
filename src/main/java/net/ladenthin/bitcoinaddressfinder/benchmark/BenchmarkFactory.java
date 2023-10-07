package net.ladenthin.bitcoinaddressfinder.benchmark;

import net.ladenthin.bitcoinaddressfinder.OpenCLContext;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.BenchmarkType;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.ChunkSizeIteratorBenchmark;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.CtxRoundsIteratorBenchmark;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.DefaultBenchmark;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds.AddressBytesRound;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds.PublicKeysRound;
import net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds.Ripemd160Round;
import net.ladenthin.bitcoinaddressfinder.configuration.CBenchmark;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;
import net.ladenthin.bitcoinaddressfinder.opencl.OpenCLBuilder;
import net.ladenthin.bitcoinaddressfinder.opencl.OpenCLPlatform;

import java.util.ArrayList;
import java.util.List;

public class BenchmarkFactory {

    public static final int MAX_GRIDNUMBITS = 24;
    public static final int MAX_TOTALROUNDS = 100;
    public static final int MAX_CTXROUNDS = 100;

    public static final int DEFAULT_GRIDNUMBITS = 8;
    public static final boolean DEFAULT_CHUNKMODE = true;
    public static final int DEFAULT_KERNELMODE = 2;
    public static final int DEFAULT_TOTAL_ROUNDS = 10;
    public static final int DEFAULT_CONTEXT_ROUNDS = 10;
    public static final boolean DEFAULT_LOGTOCONSOLE = true;

    public static final String TYPE_DEFAULT = "default";
    public static final String TYPE_CHUNK_ITERATOR = "chunkSizeIterator";
    public static final String TYPE_CTX_ITERATOR = "ctxRoundsIterator";

    private static final String ARG_GRIDNUMBITS = "gridNumBits";
    private static final String ARG_TOTAL_ROUNDS = "totalRounds";
    private static final String ARG_KERNELMODE = "kernelMode";
    private static final String ARG_CONTEXT_ROUNDS = "contextRounds";

    private final String benchmarkType;

    private final boolean chunkMode;
    private int gridNumBits;
    private int totalRounds;
    private int kernelMode;
    private int contextRounds;

    private final BenchmarkLogger logger;

    public BenchmarkFactory(CBenchmark configuration) {
        assumeOpenClWorking();
        this.benchmarkType = configuration.type;
        this.gridNumBits = configuration.gridNumBits;
        this.totalRounds = configuration.totalRounds;
        this.chunkMode = configuration.chunkMode;
        this.kernelMode = configuration.kernelMode;
        this.contextRounds = configuration.contextRounds;
        boolean logToConsole = configuration.logToConsole;
        boolean logToFile = configuration.logToFile;
        logger = new BenchmarkLogger(logToConsole, logToFile);
    }

    public BenchmarkType createBenchmarkRunner() throws BenchmarkFactoryException {
        switch (benchmarkType) {
            case TYPE_CHUNK_ITERATOR:
                return checkConfigAndCreateChunkSizeIterator();
            case TYPE_DEFAULT:
                return checkConfigAndCreateDefaultBenchmark();
            case TYPE_CTX_ITERATOR:
                return checkConfigAndCreateCtxIterator();
            default:
                logErrorAndAbort("Unknown BenchmarkType!");
        }
        return null;
    }

    public static void assumeOpenClWorking() {
        if (!OpenCLBuilder.isOpenCLnativeLibraryLoadable()) {
            logErrorAndShutdown("No OpenCL device with support of version 2.0 or greater avaiable!");
        } else {
            BenchmarkLogger.staticInfo("OpenCL native library loadable!");
        }

        OpenCLBuilder openCLBuilder = new OpenCLBuilder();
        List<OpenCLPlatform> openCLPlatforms = openCLBuilder.build();

        if (!OpenCLBuilder.isOneOpenCL2_0OrGreaterDeviceAvailable(openCLPlatforms)) {
            logErrorAndShutdown("No OpenCL device with support of version 2.0 or greater avaiable!");
        } else {
            BenchmarkLogger.staticInfo("Found device with support of OpenCL 2.0 or greater!");
        }
    }

    private static void logErrorAndShutdown(String msg) {
        BenchmarkLogger.staticError(msg);
        throw new RuntimeException(msg);
    }

    private BenchmarkType checkConfigAndCreateChunkSizeIterator() {
        checkGridNumBits();
        checkKernelMode();
        checkContextRounds();
        return new ChunkSizeIteratorBenchmark(gridNumBits, chunkMode, kernelMode, contextRounds, logger);
    }

    private BenchmarkType checkConfigAndCreateDefaultBenchmark() {
        checkGridNumBits();
        checkTotalRounds();
        checkContextRounds();
        return new DefaultBenchmark(gridNumBits, chunkMode, totalRounds, contextRounds, logger);
    }

    private BenchmarkType checkConfigAndCreateCtxIterator() {
        checkGridNumBits();
        checkKernelMode();
        checkContextRounds();
        return new CtxRoundsIteratorBenchmark(gridNumBits, chunkMode, kernelMode, contextRounds, logger);
    }

    private void checkGridNumBits() {
        if (gridNumBits < 0) {
            logWarnLimits(ARG_GRIDNUMBITS, DEFAULT_GRIDNUMBITS);
            gridNumBits = DEFAULT_GRIDNUMBITS;
        } else if (gridNumBits > MAX_GRIDNUMBITS) {
            logWarnLimits(ARG_GRIDNUMBITS, MAX_GRIDNUMBITS);
            gridNumBits = MAX_GRIDNUMBITS;
        }
    }

    private void checkKernelMode() {
        if (kernelMode == OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE) {
            return;
        }
        if (kernelMode == OpenCLContext.GEN_RIPEMD160_ONLY_MODE) {
            return;
        }
        if (kernelMode == OpenCLContext.GEN_ADDRESSES_ONLY_MODE) {
            return;
        }
        logWarnLimits(ARG_KERNELMODE, DEFAULT_KERNELMODE);
        kernelMode = DEFAULT_KERNELMODE;
    }

    private void checkTotalRounds() {
        if (totalRounds > 0 && totalRounds <= MAX_TOTALROUNDS) {
            return;
        }
        logWarnLimits(ARG_TOTAL_ROUNDS, DEFAULT_TOTAL_ROUNDS);
        totalRounds = DEFAULT_TOTAL_ROUNDS;
    }

    private void checkContextRounds() {
        if (contextRounds > 0 && contextRounds <= MAX_CTXROUNDS) {
            return;
        }
        logWarnLimits(ARG_CONTEXT_ROUNDS, DEFAULT_CONTEXT_ROUNDS);
        contextRounds = DEFAULT_CONTEXT_ROUNDS;
    }

    private void logWarnLimits(String argument, int value) {
        logger.warn("Value for " + argument + " is invalid or missing!");
        logger.warn("Will use default value: " + value);
    }

    private void logErrorAndAbort(String msg) throws BenchmarkFactoryException {
        logger.error(msg);
        throw new BenchmarkFactoryException(msg);
    }

    public static List<CProducerOpenCL> createProducers(int gridNumBits, boolean chunkMode, int kernelMode, int measuringRounds, BenchmarkLogger logger) {
        logger.info("Creating configurations...");
        List<CProducerOpenCL> producers = new ArrayList<>();
        for (int i = 0; i < measuringRounds; i++) {
            CProducerOpenCL producerOpenCL = new CProducerOpenCL();
            producerOpenCL.gridNumBits = gridNumBits;
            producerOpenCL.chunkMode = chunkMode;
            producerOpenCL.kernelMode = kernelMode;
            producers.add(producerOpenCL);
        }
        logger.info("Configurations successfully created!");
        return producers;
    }

    public static List<MeasurementRound> initializingBenchmarkRounds(int gridNumBits, boolean chunkMode, int roundsPerInitializedContext, List<CProducerOpenCL> producers, BenchmarkLogger logger) throws BenchmarkException {
        logger.info("Initializing measuring rounds...");
        List<MeasurementRound> rounds = new ArrayList<>();
        int parameterToLatex = 1;
        for (CProducerOpenCL producer : producers) {
            String parameterToPrint = "2^{" + gridNumBits + "} = " + (1 << gridNumBits) + ", " + roundsPerInitializedContext + "x/ctx, cm:" + chunkMode;
            rounds.add(createBenchmarkRound(producer, roundsPerInitializedContext, parameterToPrint, "" + parameterToLatex, logger));
            parameterToLatex++;
        }
        logger.info(rounds.size() + " measuring rounds successfully initialized!");
        return rounds;
    }

    public static MeasurementRound createBenchmarkRound(CProducerOpenCL producer, int roundsPerInitializedContext, String parameterToLatex, String parameterToPrint, BenchmarkLogger logger) {
        int kernelMode = producer.kernelMode;
        if (kernelMode == OpenCLContext.GEN_RIPEMD160_ONLY_MODE) {
            return new Ripemd160Round(producer, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
        } else if (kernelMode == OpenCLContext.GEN_XY_COORDINATES_ONLY_MODE) {
            return new PublicKeysRound(producer, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
        } else if (kernelMode == OpenCLContext.GEN_ADDRESSES_ONLY_MODE) {
            return new AddressBytesRound(producer, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
        }
        return null;
    }
}