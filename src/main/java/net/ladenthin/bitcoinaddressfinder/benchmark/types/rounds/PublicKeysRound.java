package net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds;

import net.ladenthin.bitcoinaddressfinder.InvalidWorkSizeException;
import net.ladenthin.bitcoinaddressfinder.PublicKeyBytes;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;
import net.ladenthin.bitcoinaddressfinder.benchmark.MeasurementRound;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.math.BigInteger;

public class PublicKeysRound extends MeasurementRound {

    byte[][] ripemd160BytesResults;

    public PublicKeysRound(CProducerOpenCL producerOpenCL, int roundsPerInitializedContext, String parameterToPrint, String parameterToLatex, BenchmarkLogger logger) {
        super(producerOpenCL, roundsPerInitializedContext, parameterToPrint, parameterToLatex, logger);
        ripemd160BytesResults = new byte[producerOpenCL.getWorkSize()][PublicKeyBytes.HASH160_SIZE];
    }

    @Override
    protected byte[][] executeAndReturnResults(BigInteger[][] privateKeyChunks, int roundIndex) throws InvalidWorkSizeException {
        openCLGridResults[roundIndex] = openCLContext.createResult(privateKeyChunks[roundIndex]);
        PublicKeyBytes[] publicKeyBytesResults = openCLGridResults[roundIndex].getPublicKeyBytes();
        for (int i = 0; i < publicKeyBytesResults.length; i++) {
            ripemd160BytesResults[i] = publicKeyBytesResults[i].getUncompressedKeyHash();
        }
        return ripemd160BytesResults;
    }
}