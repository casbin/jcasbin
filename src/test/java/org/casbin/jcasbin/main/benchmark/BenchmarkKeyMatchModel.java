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
 * Benchmark for RESTful/KeyMatch model.
 * 
 * <p>This benchmark tests RESTful authorization performance with pattern matching.
 * The KeyMatch model allows flexible URL pattern matching for RESTful APIs,
 * supporting wildcards and path parameters.
 * The scenario uses deterministic policy generation to ensure reproducible results across runs.
 * 
 * <p><b>Data Scale:</b>
 * <ul>
 *   <li>Total rules: 5</li>
 *   <li>Total users: 3 (alice, bob, cathy)</li>
 * </ul>
 * 
 * <p><b>Policy Structure:</b>
 * <pre>
 * p, alice, /alice_data/*, GET
 * p, alice, /alice_data/resource1, POST
 * p, bob, /alice_data/resource2, GET
 * p, bob, /bob_data/*, POST
 * p, cathy, /cathy_data, (GET)|(POST)
 * </pre>
 * 
 * <p><b>Test Case:</b> Enforce "alice", "/alice_data/resource1", "GET"
 * 
 * <p><b>Recommended JMH Options:</b>
 * <pre>
 * -f 2 -wi 3 -i 5 -t 1
 * (2 forks, 3 warmup iterations, 5 measurement iterations, 1 thread)
 * </pre>
 * 
 * @see <a href="https://casbin.org/docs/en/function#keymatch">Casbin KeyMatch Functions</a>
 */
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkKeyMatchModel {
    private static Enforcer e = new Enforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkKeyMatchModel.class.getName())
            .exclude("Pref")
            .warmupIterations(3)
            .measurementIterations(5)
            .addProfiler(GCProfiler.class)
            .forks(2)
            .threads(1)
            .build();
        new Runner(opt).run();
    }

    @Threads(1)
    @Benchmark
    public static void benchmarkKeyMatchModel() {
        e.enforce("alice", "/alice_data/resource1", "GET");
    }
}
