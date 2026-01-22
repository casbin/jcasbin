// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.jcasbin.main.benchmark;

/**
 * Utility class for running simple benchmarks without JMH.
 * Provides basic timing and throughput measurement functionality.
 */
public class BenchmarkUtil {
    
    /** Default number of warmup iterations */
    private static final int DEFAULT_WARMUP_ITERATIONS = 3;
    
    /** Default number of measurement iterations */
    private static final int DEFAULT_MEASUREMENT_ITERATIONS = 5;
    
    /**
     * Functional interface for benchmark operations.
     */
    @FunctionalInterface
    public interface BenchmarkOperation {
        void execute();
    }
    
    /**
     * Runs a benchmark operation multiple times and measures throughput.
     * 
     * @param name The name of the benchmark
     * @param warmupIterations Number of warmup iterations
     * @param measurementIterations Number of measurement iterations
     * @param operation The operation to benchmark
     */
    public static void runBenchmark(String name, int warmupIterations, int measurementIterations, BenchmarkOperation operation) {
        // Warmup phase
        for (int i = 0; i < warmupIterations; i++) {
            operation.execute();
        }
        
        // Measurement phase
        long startTime = System.nanoTime();
        for (int i = 0; i < measurementIterations; i++) {
            operation.execute();
        }
        long endTime = System.nanoTime();
        
        // Calculate and display results
        double durationSeconds = (endTime - startTime) / 1_000_000_000.0;
        double throughput = measurementIterations / durationSeconds;
        
        System.out.printf("Benchmark: %s%n", name);
        System.out.printf("  Iterations: %d%n", measurementIterations);
        System.out.printf("  Duration: %.3f seconds%n", durationSeconds);
        System.out.printf("  Throughput: %.2f ops/sec%n", throughput);
        System.out.println();
    }
    
    /**
     * Runs a benchmark operation with default settings (3 warmup iterations, 5 measurement iterations).
     * 
     * @param name The name of the benchmark
     * @param operation The operation to benchmark
     */
    public static void runBenchmark(String name, BenchmarkOperation operation) {
        runBenchmark(name, DEFAULT_WARMUP_ITERATIONS, DEFAULT_MEASUREMENT_ITERATIONS, operation);
    }
}
