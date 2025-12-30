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
 * Benchmark for RBAC model with domains/tenants.
 * 
 * <p>This benchmark tests RBAC authorization performance with multi-tenancy support.
 * Domains (also called tenants) allow isolating permissions across different organizational units.
 * The scenario uses deterministic policy generation to ensure reproducible results across runs.
 * 
 * <p><b>Data Scale:</b>
 * <ul>
 *   <li>Total rules: 6 (4 policies + 2 user-role assignments)</li>
 *   <li>Total users: 2 (alice, bob)</li>
 *   <li>Total roles: 1 (admin)</li>
 *   <li>Total domains: 2 (domain1, domain2)</li>
 * </ul>
 * 
 * <p><b>Policy Structure:</b>
 * <pre>
 * p, admin, domain1, data1, read
 * p, admin, domain1, data1, write
 * p, admin, domain2, data2, read
 * p, admin, domain2, data2, write
 * g, alice, admin, domain1
 * g, bob, admin, domain2
 * </pre>
 * 
 * <p><b>Test Case:</b> Enforce "alice", "domain1", "data1", "read"
 * 
 * <p><b>Recommended JMH Options:</b>
 * <pre>
 * -f 2 -wi 3 -i 5 -t 1
 * (2 forks, 3 warmup iterations, 5 measurement iterations, 1 thread)
 * </pre>
 * 
 * @see <a href="https://casbin.org/docs/en/rbac-with-domains">Casbin RBAC with Domains</a>
 */
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class BenchmarkRBACModelWithDomains {
    private static Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv", false);

    public static void main(String args[]) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(BenchmarkRBACModelWithDomains.class.getName())
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
    public static void benchmarkRBACModelWithDomains() {
        e.enforce("alice", "domain1", "data1", "read");
    }
}
