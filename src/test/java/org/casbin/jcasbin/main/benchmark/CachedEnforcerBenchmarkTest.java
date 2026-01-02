// Copyright 2017 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.main.CachedEnforcer;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@BenchmarkMode({Mode.Throughput, Mode.AverageTime})
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class CachedEnforcerBenchmarkTest {

    public static class TestResource {
        String name;
        String owner;

        public TestResource(String name, String owner) {
            this.name = name;
            this.owner = owner;
        }

        public String getName() {
            return name;
        }

        public String getOwner() {
            return owner;
        }
    }

    private static boolean rawEnforce(String sub, String obj, String act) {
        String[][] policy = {{"alice", "data1", "read"}, {"bob", "data2", "write"}};
        for (String[] rule : policy) {
            if (sub.equals(rule[0]) && obj.equals(rule[1]) && act.equals(rule[2])) {
                return true;
            }
        }
        return false;
    }

    private static TestResource newTestResource(String name, String owner) {
        return new TestResource(name, owner);
    }

    @Benchmark
    public void benchmarkCachedRaw() {
        rawEnforce("alice", "data1", "read");
    }

    private CachedEnforcer cachedBasicModelEnforcer;

    @Setup(Level.Trial)
    public void setupCachedBasicModel() {
        cachedBasicModelEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
    }

    @Benchmark
    public void benchmarkCachedBasicModel() {
        cachedBasicModelEnforcer.enforce("alice", "data1", "read");
    }

    private CachedEnforcer cachedRBACModelEnforcer;

    @Setup(Level.Trial)
    public void setupCachedRBACModel() {
        cachedRBACModelEnforcer = new CachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
    }

    @Benchmark
    public void benchmarkCachedRBACModel() {
        cachedRBACModelEnforcer.enforce("alice", "data2", "read");
    }

    private CachedEnforcer cachedRBACModelSmallEnforcer;

    @Setup(Level.Trial)
    public void setupCachedRBACModelSmall() {
        cachedRBACModelSmallEnforcer = new CachedEnforcer("examples/rbac_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            cachedRBACModelSmallEnforcer.addPolicy(String.format("group%d", i), String.format("data%d", i / 10), "read");
        }

        // 1000 users.
        for (int i = 0; i < 1000; i++) {
            cachedRBACModelSmallEnforcer.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i / 10));
        }
    }

    @Benchmark
    public void benchmarkCachedRBACModelSmall() {
        cachedRBACModelSmallEnforcer.enforce("user501", "data9", "read");
    }

    private CachedEnforcer cachedRBACModelMediumEnforcer;

    @Setup(Level.Trial)
    public void setupCachedRBACModelMedium() {
        cachedRBACModelMediumEnforcer = new CachedEnforcer("examples/rbac_model.conf", "");

        // 1000 roles, 100 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("group%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        cachedRBACModelMediumEnforcer.addPolicies(pPolicies);

        // 10000 users.
        List<List<String>> gPolicies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("group%d", i / 10));
            gPolicies.add(policy);
        }
        cachedRBACModelMediumEnforcer.addGroupingPolicies(gPolicies);
    }

    @Benchmark
    public void benchmarkCachedRBACModelMedium() {
        cachedRBACModelMediumEnforcer.enforce("user5001", "data150", "read");
    }

    private CachedEnforcer cachedRBACModelLargeEnforcer;

    @Setup(Level.Trial)
    public void setupCachedRBACModelLarge() {
        cachedRBACModelLargeEnforcer = new CachedEnforcer("examples/rbac_model.conf", "");

        // 10000 roles, 1000 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("group%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        cachedRBACModelLargeEnforcer.addPolicies(pPolicies);

        // 100000 users.
        List<List<String>> gPolicies = new ArrayList<>();
        for (int i = 0; i < 100000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("group%d", i / 10));
            gPolicies.add(policy);
        }
        cachedRBACModelLargeEnforcer.addGroupingPolicies(gPolicies);
    }

    @Benchmark
    public void benchmarkCachedRBACModelLarge() {
        cachedRBACModelLargeEnforcer.enforce("user50001", "data1500", "read");
    }

    private CachedEnforcer cachedRBACModelWithResourceRolesEnforcer;

    @Setup(Level.Trial)
    public void setupCachedRBACModelWithResourceRoles() {
        cachedRBACModelWithResourceRolesEnforcer = new CachedEnforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv");
    }

    @Benchmark
    public void benchmarkCachedRBACModelWithResourceRoles() {
        cachedRBACModelWithResourceRolesEnforcer.enforce("alice", "data1", "read");
    }

    private CachedEnforcer cachedRBACModelWithDomainsEnforcer;

    @Setup(Level.Trial)
    public void setupCachedRBACModelWithDomains() {
        cachedRBACModelWithDomainsEnforcer = new CachedEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");
    }

    @Benchmark
    public void benchmarkCachedRBACModelWithDomains() {
        cachedRBACModelWithDomainsEnforcer.enforce("alice", "domain1", "data1", "read");
    }

    private CachedEnforcer cachedABACModelEnforcer;
    private TestResource cachedABACTestResource;

    @Setup(Level.Trial)
    public void setupCachedABACModel() {
        cachedABACModelEnforcer = new CachedEnforcer("examples/abac_model.conf", "");
        cachedABACTestResource = newTestResource("data1", "alice");
    }

    @Benchmark
    public void benchmarkCachedABACModel() {
        cachedABACModelEnforcer.enforce("alice", cachedABACTestResource, "read");
    }

    private CachedEnforcer cachedKeyMatchModelEnforcer;

    @Setup(Level.Trial)
    public void setupCachedKeyMatchModel() {
        cachedKeyMatchModelEnforcer = new CachedEnforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv");
    }

    @Benchmark
    public void benchmarkCachedKeyMatchModel() {
        cachedKeyMatchModelEnforcer.enforce("alice", "/alice_data/resource1", "GET");
    }

    private CachedEnforcer cachedRBACModelWithDenyEnforcer;

    @Setup(Level.Trial)
    public void setupCachedRBACModelWithDeny() {
        cachedRBACModelWithDenyEnforcer = new CachedEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv");
    }

    @Benchmark
    public void benchmarkCachedRBACModelWithDeny() {
        cachedRBACModelWithDenyEnforcer.enforce("alice", "data1", "read");
    }

    private CachedEnforcer cachedPriorityModelEnforcer;

    @Setup(Level.Trial)
    public void setupCachedPriorityModel() {
        cachedPriorityModelEnforcer = new CachedEnforcer("examples/priority_model.conf", "examples/priority_policy.csv");
    }

    @Benchmark
    public void benchmarkCachedPriorityModel() {
        cachedPriorityModelEnforcer.enforce("alice", "data1", "read");
    }

    @Benchmark
    public void benchmarkCachedRBACModelMediumParallel(ThreadState state) {
        state.e.enforce("user5001", "data150", "read");
    }

    @State(Scope.Thread)
    public static class ThreadState {
        CachedEnforcer e;

        @Setup(Level.Trial)
        public void setup() {
            e = new CachedEnforcer("examples/rbac_model.conf", "");

            // 10000 roles, 1000 resources.
            List<List<String>> pPolicies = new ArrayList<>();
            for (int i = 0; i < 10000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("group%d", i));
                policy.add(String.format("data%d", i / 10));
                policy.add("read");
                pPolicies.add(policy);
            }
            e.addPolicies(pPolicies);

            // 100000 users.
            List<List<String>> gPolicies = new ArrayList<>();
            for (int i = 0; i < 100000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("user%d", i));
                policy.add(String.format("group%d", i / 10));
                gPolicies.add(policy);
            }
            e.addGroupingPolicies(gPolicies);
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(CachedEnforcerBenchmarkTest.class.getSimpleName())
                .forks(1)
                .warmupIterations(5)
                .measurementIterations(5)
                .build();
        new Runner(opt).run();
    }
}
