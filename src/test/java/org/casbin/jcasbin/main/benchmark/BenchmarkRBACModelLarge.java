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
 * Benchmark for RBAC model with large-scale data.
 * 
 * <p>This benchmark tests RBAC authorization performance with a large dataset.
 * The scenario uses deterministic policy generation to ensure reproducible results across runs.
 * 
 * <p><b>Data Scale:</b>
 * <ul>
 *   <li>Total rules: 110000 (10000 role policies + 100000 user-role assignments)</li>
 *   <li>Total users: 100000</li>
 *   <li>Total roles: 10000</li>
 *   <li>Total resources: 1000</li>
 * </ul>
 * 
 * <p><b>Generation Logic:</b>
 * <ul>
 *   <li>For each role i (0-9999): p, group{i}, data{i/10}, read</li>
 *   <li>For each user i (0-99999): g, user{i}, group{i/10}</li>
 *   <li>Each 10 roles are bound to 1 resource</li>
 *   <li>Each 10 users are bound to 1 role</li>
 * </ul>
 * 
 * <p><b>Test Case:</b> Enforce "user50001", "data1500", "read"
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
public class BenchmarkRBACModelLarge {
    private static Enforcer e = new Enforcer("examples/rbac_model.conf", "", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkRBACModelLarge.class.getName())
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
    public static void benchmarkRBACModelLarge() {
        e.enforce("user50001", "data1500", "read");
    }

    static {
        e.enableAutoBuildRoleLinks(false);
        // 10000 roles, 1000 resources.
        for (int i = 0; i < 10000; i++) {
            e.addPolicy(String.format("group%d", i), String.format("data%d", i/10), "read");
        }
        // 100000 users.
        for (int i = 0; i < 100000; i++) {
            e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i/10));
        }
        e.buildRoleLinks();
    }
}
