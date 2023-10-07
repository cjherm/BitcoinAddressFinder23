package net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds;

import net.ladenthin.bitcoinaddressfinder.InvalidWorkSizeException;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;
import net.ladenthin.bitcoinaddressfinder.benchmark.MeasurementRound;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.math.BigInteger;

public class PublicKeysRound extends MeasurementRound {

    public PublicKeysRound(CProducerOpenCL producerOpenCL, int roundsPerInitializedContext, String parameterToPrint, String parameterToLatex, BenchmarkLogger logger) {
        super(producerOpenCL, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
    }

    @Override
    protected byte[][] executeAndReturnResults(BigInteger[][] privateKeyChunks, int roundIndex) throws InvalidWorkSizeException {
        return new byte[0][];
    }
}