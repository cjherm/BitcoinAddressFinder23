package net.ladenthin.bitcoinaddressfinder.benchmark;

public class BenchmarkException extends Throwable {

    private final Throwable e;

    public BenchmarkException(String msg) {
        super(msg);
        this.e = new Throwable();
    }

    public BenchmarkException(String msg, Throwable e) {
        super(msg);
        this.e = e;
    }

    public Throwable getInitialThrowable() {
        return e;
    }
}