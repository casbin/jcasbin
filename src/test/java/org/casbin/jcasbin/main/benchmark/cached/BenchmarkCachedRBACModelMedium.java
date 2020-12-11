package org.casbin.jcasbin.main.benchmark.cached;

import org.casbin.jcasbin.main.CachedEnforcer;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkCachedRBACModelMedium {
    private static CachedEnforcer e = new CachedEnforcer("examples/rbac_model.conf", "", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkCachedRBACModelMedium.class.getName())
            .exclude("Pref")
            .warmupIterations(3)
            .measurementIterations(1)
            .addProfiler(GCProfiler.class)
            .forks(1)
            .build();
        new Runner(opt).run();
    }

    @Threads(1)
    @Benchmark
    public static void benchmarkCachedRBACModelMedium() {
        for (int i = 0; i < 10000; i++) {
            e.enforce("user5001", "data150", "read");
        }
    }

    static {
        e.enableAutoBuildRoleLinks(false);
        // 1000 roles, 100 resources.
        e.enableAutoBuildRoleLinks(false);
        for (int i=0;i<1000;i++) {
            e.addPolicy(String.format("group%d", i), String.format("data%d", i/10), "read");
        }
        for (int i=0;i<10000;i++) {
            e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i/10));
        }
        e.buildRoleLinks();
    }
}
