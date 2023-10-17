{
    "command" : "BenchmarkSeries",
    "benchmarkSeries" : {
        "benchmarks" : [
            {
            "type" : "chunkSizeIterator",
            "gridNumBits" : 18,
            "chunkMode" : true,
            "kernelMode" : 2,
            "contextRounds" : 1,
            "logToConsole" : null,
            "logToFile" : null
            },
            {
            "type" : "chunkSizeIterator",
            "gridNumBits" : 18,
            "chunkMode" : false,
            "kernelMode" : 2,
            "contextRounds" : 1,
            "logToConsole" : null,
            "logToFile" : null
            }
        ],
        "logToConsole" : true,
        "logToFile" : true
    }
}