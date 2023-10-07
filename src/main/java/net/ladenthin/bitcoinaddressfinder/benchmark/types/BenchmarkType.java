package net.ladenthin.bitcoinaddressfinder.benchmark.types;

public interface BenchmarkType {

    void start();

    int getTotalNumberOfResults();

    String getName();
}