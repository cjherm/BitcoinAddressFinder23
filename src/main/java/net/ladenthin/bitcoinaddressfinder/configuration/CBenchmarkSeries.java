package net.ladenthin.bitcoinaddressfinder.configuration;

import net.ladenthin.bitcoinaddressfinder.benchmark.BenchmarkFactory;

import java.util.ArrayList;
import java.util.List;

public class CBenchmarkSeries {

    public List<CBenchmark> benchmarks = new ArrayList<>();

    public boolean logToConsole = BenchmarkFactory.DEFAULT_LOGTOCONSOLE;

    public boolean logToFile = BenchmarkFactory.DEFAULT_LOGTOFILE;
}