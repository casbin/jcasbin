package org.casbin.jcasbin.main.benchmark;

import org.junit.Test;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

public class BenchmarkRunner {

    public static void main(String[] args) throws Exception {
        run();
    }

    @Test
    public void testBenchmark() throws Exception {
        run();
    }

    public static void run() throws Exception {
        String mode = System.getenv("BENCHMARK_MODE");
        boolean isCI = "true".equals(System.getenv("CI"));

        // Mode fallback logic
        if (mode == null || mode.isEmpty()) {
            if (isCI) {
                mode = "SMOKE";
            } else {
                mode = "AGILE";
            }
        }

        System.out.println(">>> Benchmark Mode: " + mode + " <<<");

        ChainedOptionsBuilder opt = new OptionsBuilder()
            .include("org.casbin.jcasbin.main.benchmark.*")
            .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.JSON)
            .result("jmh-result.json");

        switch (mode.toUpperCase()) {
            case "SMOKE":
                // SMOKE: Fast check for PRs (< 2 min)
                opt.forks(1)
                   .warmupIterations(1)
                   .measurementIterations(3)
                   .warmupTime(TimeValue.seconds(1))
                   .measurementTime(TimeValue.seconds(1))
                   // Restrict params to cover only critical path
                   .param("modelType", "rbac")
                   .param("dataScale", "medium")
                   .param("useCache", "false")
                   .param("currentRuleSize", "10000")
                   .param("scenario", "RBAC_Medium");
                break;

            case "AGILE":
                // AGILE: Local dev / Daily monitoring (~15 min)
                // Full coverage but fast iterations (matches go-casbin default)
                opt.forks(1)
                   .warmupIterations(1)
                   .measurementIterations(3)
                   .warmupTime(TimeValue.seconds(1))
                   .measurementTime(TimeValue.seconds(1));
                // No param overrides -> runs all combinations
                break;

            case "STRICT":
                // STRICT: Release / Arbitration (~3 hours)
                // Gold standard
                opt.forks(2)
                   .warmupIterations(5)
                   .measurementIterations(5)
                   .warmupTime(TimeValue.seconds(10))
                   .measurementTime(TimeValue.seconds(10));
                // No param overrides
                break;

            default:
                throw new IllegalArgumentException("Unknown BENCHMARK_MODE: " + mode);
        }

        // Allow system property overrides for manual tweaking (e.g. -Djmh.f=1)
        String forks = System.getProperty("jmh.f");
        if (forks != null) opt.forks(Integer.parseInt(forks));

        new Runner(opt.build()).run();
    }
}
