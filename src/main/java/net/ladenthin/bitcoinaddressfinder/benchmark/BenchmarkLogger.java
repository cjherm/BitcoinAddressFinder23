package net.ladenthin.bitcoinaddressfinder.benchmark;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class BenchmarkLogger {

    public int maxLogPackageSize = 25;

    private static final DateTimeFormatter DATE_TIME_LOG_FORMAT = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");
    private static final DateTimeFormatter DATE_TIME_FILENAME_FORMAT = DateTimeFormatter.ofPattern("yyyy_MM_dd__HH_mm_ss");
    private static final String LOG_INFO = "[INFO]  ";
    private static final String LOG_WARN = "[WARN]  ";
    private static final String LOG_RESULT = "[RESULT]";
    private static final String LOG_ERROR = "[ERROR] ";

    private File logFile;
    private final boolean logToFileFlag;
    private final boolean logToConsoleFlag;
    private final List<String> loggingQueue = new ArrayList<>();

    public BenchmarkLogger(boolean logToConsoleFlag, boolean logToFileFlag) {
        this.logToConsoleFlag = logToConsoleFlag;
        this.logToFileFlag = logToFileFlag;
    }

    public BenchmarkLogger(boolean logToConsoleFlag, boolean logToFileFlag, String fileNameDescriptor) {
        this.logToConsoleFlag = logToConsoleFlag;
        this.logToFileFlag = logToFileFlag;
        initLogFile(fileNameDescriptor);
    }

    public static void staticInfo(String msg) {
        System.out.println(createLogLine(LOG_INFO, msg));
    }

    public static void staticError(String msg) {
        System.out.println(createLogLine(LOG_ERROR, msg));
    }

    public void initLogFile(String fileNameDescriptor) {
        if (logFile == null) {
            String logFileName = "log__" + fileNameDescriptor.trim() + "__" + createCurrentTimeStamp(DATE_TIME_FILENAME_FORMAT) + ".txt";
            File folder = new File("benchmark_log");
            folder.mkdirs();
            logFile = new File(folder.getAbsolutePath() + File.separator + logFileName);
            info("Logger set! File: " + logFile.getAbsolutePath());
            flush();
        }
    }

    public void info(String msg) {
        log(LOG_INFO, msg);
    }

    public void warn(String msg) {
        log(LOG_WARN, msg);
    }

    public void error(String msg) {
        log(LOG_ERROR, msg);
    }

    public void info(List<String> msgList) {
        for (String msg : msgList) {
            info(msg);
        }
    }

    public void roundResult(MeasurementRoundResult result) {
        log(LOG_RESULT, result.getResultsString());
        log(LOG_RESULT, "----------------------------------------------------------------------------------------------------");
    }

    public void consoleError(String msg) {
        logToConsole(createLogLine(LOG_ERROR, msg));
    }

    private void log(String type, String msg) {
        String logLine = createLogLine(type, msg);
        logToFile(logLine);
        logToConsole(logLine);
    }

    private void logToConsole(String logLine) {
        if (logToConsoleFlag) {
            System.out.println(logLine);
        }
    }

    private void log(String type, List<String> msgList) {
        for (String msg : msgList) {
            log(type, msg);
        }
    }

    private void logToFile(String logLine) {
        loggingQueue.add(logLine);
        if (logToFileFlag && (loggingQueue.size() >= maxLogPackageSize)) {
            flush();
        }
    }

    private static String createLogLine(String type, String msg) {
        return createCurrentTimeStamp(DATE_TIME_LOG_FORMAT) + " " + type + " " + msg;
    }

    private static String createCurrentTimeStamp(DateTimeFormatter dateTimeFormat) {
        LocalDateTime currentTime = LocalDateTime.now();
        return currentTime.format(dateTimeFormat);
    }

    public void flush() {
        if (logToFileFlag) {
            writeInFile();
        }
    }

    private void writeInFile() {
        if (logFile != null) {
            try {
                FileOutputStream fos = new FileOutputStream(logFile);
                BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));
                for (String line : loggingQueue) {
                    bw.write(line);
                    bw.newLine();
                }
                bw.close();
            } catch (IOException e) {
                consoleError(e.getMessage());
            }
        } else {
            staticError("Log file was not initialized! No logging into a file!");
        }
    }

    public void startBenchmark(String benchmarkName, int kernelMode, int gridNumBits, boolean chunkMode, int roundsPerInitializedContext, int measuringRounds) {
        info("========================================" + benchmarkName + "========================================");
        info("KernelMode = " + kernelMode + ", gridNumBits = " + gridNumBits + ", chunkSize = " + (1 << gridNumBits) + ", chunkMode = " + chunkMode);
        info("Rounds per initialized context: " + roundsPerInitializedContext);
        info("Starting benchmark rounds (" + measuringRounds + " in total)!");
        info("----------------------------------------------------------------------------------------------------");
    }

    public void result(String msg) {
        log(LOG_RESULT, msg);
    }

    public void logFinalResults(long benchmarkStart, long benchmarkFinish, List<MeasurementRoundResult> measurementRoundResults) {
        // TODO impl
    }
}