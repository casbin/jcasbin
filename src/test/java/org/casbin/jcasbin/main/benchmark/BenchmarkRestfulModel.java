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

/**
 * Benchmark for RESTful (KeyMatch) model.
 * Data scale: 5 rules (3 users).
 */
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkRestfulModel {
    private static Enforcer e;

    static {
        e = new Enforcer("examples/keymatch_model.conf", "", false);
        e.enableAutoBuildRoleLinks(false);
        e.addPolicy("alice", "/alice_data/*", "GET");
        e.addPolicy("alice", "/alice_data/resource1", "POST");
        e.addPolicy("bob", "/alice_data/resource2", "GET");
        e.addPolicy("bob", "/bob_data/*", "POST");
        e.addPolicy("cathy", "/cathy_data", "(GET)|(POST)");
        e.buildRoleLinks();
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(BenchmarkRestfulModel.class.getName())
                .exclude("Pref")
                .warmupIterations(3)
                .measurementIterations(5)
                .addProfiler(GCProfiler.class)
                .forks(2)
                .build();
        new Runner(opt).run();
    }

    @Threads(1)
    @Benchmark
    public void benchmarkRestfulModel() {
        e.enforce("alice", "/alice_data/resource1", "GET");
    }
}
