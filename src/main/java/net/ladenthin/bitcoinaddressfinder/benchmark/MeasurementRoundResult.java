package net.ladenthin.bitcoinaddressfinder.benchmark;

public class MeasurementRoundResult {

    private final String parameter;
    private final String parameterToLatex;
    private final double roundDurationInSeconds;
    private final int resultsPerSecond;
    private final int numberOfResults;

    public MeasurementRoundResult(String parameter, String parameterToLatex, long roundStart, long roundFinish, int numberOfResults) {
        this.parameter = parameter;
        this.parameterToLatex = parameterToLatex;
        this.roundDurationInSeconds = ((double) roundFinish - (double) roundStart) / 1000;
        this.numberOfResults = numberOfResults;
        this.resultsPerSecond = (int) (numberOfResults / roundDurationInSeconds);
    }

    public int getNumberOfResults() {
        return numberOfResults;
    }
}