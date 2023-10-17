{
    "command" : "BenchmarkSeries",
    "benchmarkSeries" : {
        "benchmarks" : [
            {
            "type" : "ctxRoundsIterator",
            "gridNumBits" : 18,
            "chunkMode" : true,
            "kernelMode" : 2,
            "contextRounds" : 25,
            "logToConsole" : null,
            "logToFile" : null
            },
            {
            "type" : "ctxRoundsIterator",
            "gridNumBits" : 18,
            "chunkMode" : false,
            "kernelMode" : 2,
            "contextRounds" : 25,
            "logToConsole" : null,
            "logToFile" : null
            }
        ],
        "logToConsole" : true,
        "logToFile" : true
    }
}