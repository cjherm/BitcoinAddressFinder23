package net.ladenthin.bitcoinaddressfinder.configuration;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactory;

public class CBenchmark {

    public String type;

    public int gridNumBits = BenchmarkFactory.DEFAULT_GRIDNUMBITS;

    public boolean chunkMode = BenchmarkFactory.DEFAULT_CHUNKMODE;

    public int kernelMode = BenchmarkFactory.DEFAULT_KERNELMODE;

    public int totalRounds = BenchmarkFactory.DEFAULT_TOTAL_ROUNDS;

    public int contextRounds = BenchmarkFactory.DEFAULT_CONTEXT_ROUNDS;

    public boolean logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;

    public boolean logToFile = BenchmarkFactory.DEFAULT_LOGTOFILE;
}