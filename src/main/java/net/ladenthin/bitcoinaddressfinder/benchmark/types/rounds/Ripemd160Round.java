package net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds;

import net.ladenthin.bitcoinaddressfinder.InvalidWorkSizeException;
import net.ladenthin.bitcoinaddressfinder.Ripemd160Bytes;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;
import net.ladenthin.bitcoinaddressfinder.benchmark.MeasurementRound;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.math.BigInteger;

public class Ripemd160Round extends MeasurementRound {

    byte[][] ripemd160BytesResults;

    public Ripemd160Round(CProducerOpenCL producerOpenCL, int roundsPerInitializedContext, String parameterToPrint, String parameterToLatex, BenchmarkLogger logger) {
        super(producerOpenCL, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
        ripemd160BytesResults = new byte[producerOpenCL.getWorkSize()][Ripemd160Bytes.NUM_BYTES_RIPEMD160];
    }

    @Override
    protected byte[][] executeAndReturnResults(BigInteger[][] privateKeyChunks, int roundIndex) throws InvalidWorkSizeException {
        openCLGridResults[roundIndex] = openCLContext.createResult(privateKeyChunks[roundIndex]);
        Ripemd160Bytes[] ripemd160Bytes = openCLGridResults[roundIndex].getRipemd160Bytes();
        for (int i = 0; i < ripemd160Bytes.length; i++) {
            ripemd160BytesResults[i] = ripemd160Bytes[i].getRipemd160Hash();
        }
        return ripemd160BytesResults;
    }
}