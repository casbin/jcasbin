package org.casbin.jcasbin.main.benchmark.synced;

import org.casbin.jcasbin.main.SyncedEnforcer;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkSyncedRBACModelSmall {
    private static SyncedEnforcer e = new SyncedEnforcer("examples/rbac_model.conf", "", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkSyncedRBACModelSmall.class.getName())
            .exclude("Pref")
            .warmupIterations(3)
            .measurementIterations(1)
            .addProfiler(GCProfiler.class)
            .forks(1)
            .build();
        new Runner(opt).run();
    }

    @Threads(Threads.MAX)
    @Benchmark
    public static void benchmarkRBACModelSmall() {
        for (int i = 0; i < 1000; i++) {
            e.enforce("user501", "data9", "read");
        }
    }

    static {
        e.enableAutoBuildRoleLinks(false);
        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            e.addPolicy(String.format("group%d", i), String.format("data%d", i/10), "read");
        }
        // 1000 users.
        for (int i = 0; i < 1000; i++) {
            e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i/10));
        }
        e.buildRoleLinks();
    }
}
