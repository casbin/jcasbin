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
public class BenchmarkKeyMatchModel {
    @State(Scope.Benchmark)
    public static class BenchmarkState {
        private Enforcer e;
        private Enforcer e2;

        @Setup(Level.Trial)
        public void setup() {
            e = new Enforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv", false);
            e2 = new Enforcer("examples/keymatch2_model.conf", "examples/keymatch2_policy.csv", false);
        }
    }

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkKeyMatchModel.class.getName())
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
    public void benchmarkKeyMatchModel(BenchmarkState state) {
        state.e.enforce("alice", "/alice_data/resource1", "GET");
    }

    @Threads(1)
    @Benchmark
    public void benchmarkKeyMatch2Model(BenchmarkState state) {
        state.e2.enforce("alice", "/alice_data/resource1", "GET");
    }
}
