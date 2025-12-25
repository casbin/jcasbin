// Copyright 2020 The casbin Authors. All Rights Reserved.
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
public class BenchmarkRBACModelSmall {
    private static Enforcer e;

    static {
        e = new Enforcer("examples/rbac_model.conf", "", false);
        e.enableAutoBuildRoleLinks(false);
        for (int i = 0; i < 100; i++) {
            e.addPolicy(String.format("group%d", i), String.format("data%d", i / 10), "read");
        }
        for (int i = 0; i < 1000; i++) {
            e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i / 10));
        }
        e.buildRoleLinks();
    }

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkRBACModelSmall.class.getName())
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
    public void benchmarkRBACModelSmall() {
        e.enforce("user501", "data9", "read");
    }
}
