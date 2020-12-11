package org.casbin.jcasbin.main.benchmark.cached;

import org.casbin.jcasbin.main.CachedEnforcer;
import org.casbin.jcasbin.main.Enforcer;
import org.casbin.jcasbin.main.ModelUnitTest;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkCachedABACModel {
    private static CachedEnforcer e = new CachedEnforcer("examples/abac_model.conf", "",false);
    private static ModelUnitTest.TestResource data1 = new ModelUnitTest.TestResource("data1", "alice");

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkCachedABACModel.class.getName())
            .exclude("Pref")
            .warmupIterations(3)
            .measurementIterations(3)
            .addProfiler(GCProfiler.class)
            .forks(1)
            .build();
        new Runner(opt).run();
    }

    @Threads(1)
    @Benchmark
    public static void benchmarkCachedABACModel() {
        for (int i = 0; i < 1000; i++) {
            e.enforce("alice", data1, "read");
        }
    }
}
