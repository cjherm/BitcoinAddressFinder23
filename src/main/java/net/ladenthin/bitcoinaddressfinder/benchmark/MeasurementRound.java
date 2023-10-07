package net.ladenthin.bitcoinaddressfinder.benchmark;

import net.ladenthin.bitcoinaddressfinder.*;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;
import org.jocl.CLException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public abstract class MeasurementRound {

    protected final CProducerOpenCL producerOpenCL;
    protected final int roundsPerInitializedContext;
    protected final String parameterToPrint;
    protected final String parameterToLatex;
    protected final BenchmarkLogger logger;
    protected int numberOfTotalResults;
    protected int numberOfResultsPerContextRound;
    protected OpenCLGridResult[] openCLGridResults;
    protected OpenCLContext openCLContext;
    protected BigInteger[][] privateKeyChunks;

    public MeasurementRound(CProducerOpenCL producerOpenCL, int roundsPerInitializedContext, String parameterToPrint, String parameterToLatex, BenchmarkLogger logger) {
        this.producerOpenCL = producerOpenCL;
        this.roundsPerInitializedContext = roundsPerInitializedContext;
        this.parameterToPrint = parameterToPrint;
        this.parameterToLatex = parameterToLatex;
        this.logger = logger;
    }

    public void init() throws BenchmarkException {

        privateKeyChunks = createPrivateKeyChunks();

        numberOfTotalResults = 0;
        numberOfResultsPerContextRound = producerOpenCL.getWorkSize();

        openCLContext = new OpenCLContext(producerOpenCL);
        try {
            openCLContext.init();
        } catch (IOException | UnknownKernelModeException e) {
            openCLContext.release();
            throw new BenchmarkException("Error when trying to initialize OpenCLContext!", e);
        }
        logger.info("OpenCLContext initialized!");
        openCLGridResults = new OpenCLGridResult[roundsPerInitializedContext];
    }

    public MeasurementRoundResult start() throws BenchmarkException {
        final long roundStart, roundFinish;
        try {
            byte[][] resultedByteArray = null;
            init();
            roundStart = System.currentTimeMillis();
            for (int i = 0; i < roundsPerInitializedContext; i++) {
                resultedByteArray = executeAndReturnResults(privateKeyChunks, i);
            }
            roundFinish = System.currentTimeMillis();
            countResultsAndCleanUp(resultedByteArray);
        } catch (InvalidWorkSizeException | IllegalArgumentException | CLException e) {
            throw new BenchmarkException("Error when trying to create result!", e);
        } finally {
            if (openCLContext != null) {
                openCLContext.release();
            } else {
                logger.error("OpenCLContext is NULL and cannot be released!");
            }
        }
        return new MeasurementRoundResult(parameterToPrint, parameterToLatex, roundStart, roundFinish, numberOfTotalResults);
    }

    private void countResultsAndCleanUp(byte[][] resultedByteArray) {
        for (int i = 0; i < roundsPerInitializedContext; i++) {
            if (openCLGridResults[i] != null && resultedByteArray != null) {
                numberOfTotalResults += resultedByteArray.length;
                openCLGridResults[i].freeResult();
            }
        }
    }

    protected abstract byte[][] executeAndReturnResults(BigInteger[][] privateKeyChunks, int roundIndex) throws InvalidWorkSizeException;

    private BigInteger[][] createPrivateKeyChunks() {
        BigInteger[][] privateKeyChunks;
        int numberOfKeys;
        if (producerOpenCL.chunkMode) {
            numberOfKeys = 1;
            privateKeyChunks = new BigInteger[roundsPerInitializedContext][1];
        } else {
            numberOfKeys = producerOpenCL.getWorkSize();
            privateKeyChunks = new BigInteger[roundsPerInitializedContext][numberOfKeys];
        }
        for (int i = 0; i < roundsPerInitializedContext; i++) {
            privateKeyChunks[i] = createPrivateKeys(numberOfKeys);
        }
        logger.info((numberOfKeys * roundsPerInitializedContext) + " privateKey/s created!");
        return privateKeyChunks;
    }

    private BigInteger[] createPrivateKeys(final int numberOfKeys) {
        BigInteger[] privateKeysLocal = new BigInteger[numberOfKeys];
        for (int i = 0; i < numberOfKeys; i++) {
            privateKeysLocal[i] = createPrivateKey();
        }
        return privateKeysLocal;
    }

    private BigInteger createPrivateKey() {
        return KeyUtility.createSecret(PublicKeyBytes.PRIVATE_KEY_MAX_NUM_BITS, new SecureRandom());
    }
}