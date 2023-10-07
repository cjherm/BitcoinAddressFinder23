package net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds;

import net.ladenthin.bitcoinaddressfinder.InvalidWorkSizeException;
import net.ladenthin.bitcoinaddressfinder.ResultBytes;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;
import net.ladenthin.bitcoinaddressfinder.benchmark.MeasurementRound;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.math.BigInteger;

public class ResultBytesRound extends MeasurementRound {

    byte[][] addressBytesResults;

    public ResultBytesRound(CProducerOpenCL producer, int roundsPerInitializedContext, String parameterToPrint, String parameterToLatex, BenchmarkLogger logger) {
        super(producer, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
        addressBytesResults = new byte[producerOpenCL.getWorkSize()][ResultBytes.NUM_BYTES_ADDRESS];
    }

    @Override
    protected byte[][] executeAndReturnResults(BigInteger[][] privateKeyChunks, int roundIndex) throws InvalidWorkSizeException {
        openCLGridResults[roundIndex] = openCLContext.createResult(privateKeyChunks[roundIndex]);
        ResultBytes[] resultBytes = openCLGridResults[roundIndex].getResultBytes();
        for (int i = 0; i < resultBytes.length; i++) {
            addressBytesResults[i] = resultBytes[i].getAddressBytes();
        }
        return addressBytesResults;
    }
}