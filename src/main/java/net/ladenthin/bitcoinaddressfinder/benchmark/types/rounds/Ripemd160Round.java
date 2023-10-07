package net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;
import net.ladenthin.bitcoinaddressfinder.benchmark.MeasurementRound;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.math.BigInteger;

public class Ripemd160Round extends MeasurementRound {

    public Ripemd160Round(CProducerOpenCL producerOpenCL, int roundsPerInitializedContext, String parameterToPrint, String parameterToLatex, BenchmarkLogger logger) {
        super(producerOpenCL, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
    }

    @Override
    protected byte[][] executeAndReturnResults(BigInteger[][] privateKeyChunks, int roundIndex) {
        return new byte[0][];
    }
}