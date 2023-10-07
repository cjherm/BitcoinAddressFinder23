package net.ladenthin.bitcoinaddressfinder.benchmark.util;

import net.ladenthin.bitcoinaddressfinder.benchmark.MeasurementRoundResult;

import java.util.List;

public class LatexContentCreator {

    public static String createLatexPlotOutOfResults(List<MeasurementRoundResult> results) {
        StringBuilder latexLine = new StringBuilder("LATEX PLOT:  \\addplot coordinates {");
        for (MeasurementRoundResult result : results) {
            latexLine.append(" ").append(createPlotElem(result.getParameterToLatex(), result.getResultsPerSecond()));
        }
        latexLine.append(" };");
        return latexLine.toString();
    }

    private static String createPlotElem(String key, int value) {
        value /= 1000;
        return createPlotElem(key, String.valueOf(value));
    }

    private static String createPlotElem(String key, String value) {
        return "(" + key + "," + value + ")";
    }

    public static String createLatexTableContent(List<MeasurementRoundResult> results) {
        StringBuilder latexLine = new StringBuilder();
        latexLine.append("LATEX TABLE: ");
        for (MeasurementRoundResult result : results) {
            int resultsPerSecond = result.getResultsPerSecond() / 1000;
            latexLine.append("& ").append(resultsPerSecond).append(" ");
        }
        latexLine.append("\\\\");
        return latexLine.toString();
    }
}