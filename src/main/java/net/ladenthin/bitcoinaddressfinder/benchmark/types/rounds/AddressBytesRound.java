package net.ladenthin.bitcoinaddressfinder.benchmark.types.rounds;

import net.ladenthin.bitcoinaddressfinder.AddressBytes;
import net.ladenthin.bitcoinaddressfinder.InvalidWorkSizeException;
import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkLogger;
import net.ladenthin.bitcoinaddressfinder.benchmark.MeasurementRound;
import net.ladenthin.bitcoinaddressfinder.configuration.CProducerOpenCL;

import java.math.BigInteger;

public class AddressBytesRound extends MeasurementRound {

    byte[][] addressBytesResults;

    public AddressBytesRound(CProducerOpenCL producer, int contextRounds, String parameterToPrint, String parameterToLatex, BenchmarkLogger logger) {
        super(producer, contextRounds, parameterToPrint, parameterToLatex, logger);
        addressBytesResults = new byte[producerOpenCL.getWorkSize()][AddressBytes.NUM_BYTES_ADDRESS];
    }

    @Override
    protected byte[][] executeAndReturnResults(BigInteger[][] privateKeyChunks, int roundIndex) throws InvalidWorkSizeException {
        openCLGridResults[roundIndex] = openCLContext.createResult(privateKeyChunks[roundIndex]);
        AddressBytes[] addressBytes = openCLGridResults[roundIndex].getAddressBytes();
        for (int i = 0; i < addressBytes.length; i++) {
            addressBytesResults[i] = addressBytes[i].getAddress();
        }
        return addressBytesResults;
    }
}