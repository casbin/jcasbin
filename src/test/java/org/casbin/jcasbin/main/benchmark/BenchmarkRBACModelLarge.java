package org.casbin.jcasbin.main.benchmark;

import org.casbin.jcasbin.main.Enforcer;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkRBACModelLarge {
    private static Enforcer e = new Enforcer("examples/rbac_model.conf", "", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkRBACModelLarge.class.getName())
            .exclude("Pref")
            .warmupIterations(1)
            .measurementIterations(1)
            .addProfiler(GCProfiler.class)
            .forks(1)
            .build();
        new Runner(opt).run();
    }

    @Threads(1)
    @Benchmark
    public static void benchmarkRBACModelLarge() {
        for (int i = 0; i < 100000; i++) {
            e.enforce("user50001", "data1500", "read");
        }
    }

    static {
        e.enableAutoBuildRoleLinks(false);
        // 10000 roles, 1000 resources.
        e.enableAutoBuildRoleLinks(false);
        for (int i=0;i<10000;i++) {
            e.addPolicy(String.format("group%d", i), String.format("data%d", i/10), "read");
        }
        for (int i=0;i<100000;i++) {
            e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i/10));
        }
        e.buildRoleLinks();
    }
}
