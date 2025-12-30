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
 * Benchmark for priority-based model.
 * 
 * <p>This benchmark tests priority-based authorization performance.
 * The priority model allows policy evaluation based on explicit priority ordering,
 * where higher priority policies override lower priority ones.
 * The scenario uses deterministic policy generation to ensure reproducible results across runs.
 * 
 * <p><b>Data Scale:</b>
 * <ul>
 *   <li>Total rules: 9 (7 policies + 2 role assignments)</li>
 *   <li>Total users: 2 (alice, bob)</li>
 *   <li>Total roles: 2 (data1_deny_group, data2_allow_group)</li>
 * </ul>
 * 
 * <p><b>Policy Structure:</b>
 * <pre>
 * p, alice, data1, read, allow
 * p, data1_deny_group, data1, read, deny
 * p, data1_deny_group, data1, write, deny
 * p, alice, data1, write, allow
 * g, alice, data1_deny_group
 * p, data2_allow_group, data2, read, allow
 * p, bob, data2, read, deny
 * p, bob, data2, write, deny
 * g, bob, data2_allow_group
 * </pre>
 * 
 * <p><b>Test Case:</b> Enforce "alice", "data1", "read"
 * 
 * <p><b>Recommended JMH Options:</b>
 * <pre>
 * -f 2 -wi 3 -i 5 -t 1
 * (2 forks, 3 warmup iterations, 5 measurement iterations, 1 thread)
 * </pre>
 * 
 * @see <a href="https://casbin.org/docs/en/syntax-for-models#policy-effect">Casbin Priority Model</a>
 */
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkPriorityModel {
    private static Enforcer e = new Enforcer("examples/priority_model.conf", "examples/priority_policy.csv", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkPriorityModel.class.getName())
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
    public static void benchmarkPriorityModel() {
        e.enforce("alice", "data1", "read");
    }
}
