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

    public String getParameter() {
        return parameter;
    }

    public double getRoundDurationInSeconds() {
        return roundDurationInSeconds;
    }


    public int getNumberOfResults() {
        return numberOfResults;
    }

    public int getResultsPerSecond() {
        return resultsPerSecond;
    }

    public String getResultsString() {
        return "PARAM: {" + parameter + "}, RESULTS: " + numberOfResults + ", DURATION: " + roundDurationInSeconds + "s, RESULTS/SECOND: " + resultsPerSecond;
    }

    public String getParameterToLatex() {
        return parameterToLatex;
    }
}