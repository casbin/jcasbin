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
 * Benchmark for basic RBAC (Role-Based Access Control) model.
 * 
 * <p>This benchmark tests RBAC authorization performance with a single role assignment.
 * The scenario uses deterministic policy generation to ensure reproducible results across runs.
 * 
 * <p><b>Data Scale:</b>
 * <ul>
 *   <li>Total rules: 5 (4 policies + 1 role assignment)</li>
 *   <li>Total users: 2 (alice, bob)</li>
 *   <li>Total roles: 1 (data2_admin)</li>
 * </ul>
 * 
 * <p><b>Policy Structure:</b>
 * <pre>
 * p, alice, data1, read
 * p, bob, data2, write
 * p, data2_admin, data2, read
 * p, data2_admin, data2, write
 * g, alice, data2_admin
 * </pre>
 * 
 * <p><b>Test Case:</b> Enforce "alice", "data2", "read"
 * 
 * <p><b>Recommended JMH Options:</b>
 * <pre>
 * -f 2 -wi 3 -i 5 -t 1
 * (2 forks, 3 warmup iterations, 5 measurement iterations, 1 thread)
 * </pre>
 * 
 * @see <a href="https://casbin.org/docs/en/supported-models#rbac">Casbin RBAC Model</a>
 */
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkRBACModelSingle {
    private static Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkRBACModelSingle.class.getName())
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
    public static void benchmarkRBACModel() {
        e.enforce("alice", "data2", "read");
    }
}
