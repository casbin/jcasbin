// Copyright 2022 The casbin Authors. All Rights Reserved.
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
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
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
public class RoleManagerBenchmarkTest {

    private RoleManager rmSmall;

    @Setup(Level.Trial)
    public void setupRoleManagerSmall() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "");
        // Do not rebuild the role inheritance relations for every AddGroupingPolicy() call.
        e.enableAutoBuildRoleLinks(false);

        // 100 roles, 10 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("group%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        e.addPolicies(pPolicies);

        // 1000 users.
        List<List<String>> gPolicies = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("group%d", i / 10));
            gPolicies.add(policy);
        }
        e.addGroupingPolicies(gPolicies);

        rmSmall = e.getRoleManager();
    }

    @Benchmark
    public void benchmarkRoleManagerSmall() {
        for (int j = 0; j < 100; j++) {
            rmSmall.hasLink("user501", String.format("group%d", j));
        }
    }

    private RoleManager rmMedium;

    @Setup(Level.Trial)
    public void setupRoleManagerMedium() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "");
        // Do not rebuild the role inheritance relations for every AddGroupingPolicy() call.
        e.enableAutoBuildRoleLinks(false);

        // 1000 roles, 100 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("group%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        e.addPolicies(pPolicies);

        // 10000 users.
        List<List<String>> gPolicies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("group%d", i / 10));
            gPolicies.add(policy);
        }
        e.addGroupingPolicies(gPolicies);

        e.buildRoleLinks();

        rmMedium = e.getRoleManager();
    }

    @Benchmark
    public void benchmarkRoleManagerMedium() {
        for (int j = 0; j < 1000; j++) {
            rmMedium.hasLink("user501", String.format("group%d", j));
        }
    }

    private RoleManager rmLarge;

    @Setup(Level.Trial)
    public void setupRoleManagerLarge() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "");

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

        rmLarge = e.getRoleManager();
    }

    @Benchmark
    public void benchmarkRoleManagerLarge() {
        for (int j = 0; j < 10000; j++) {
            rmLarge.hasLink("user501", String.format("group%d", j));
        }
    }

    private Enforcer buildRoleLinksWithPatternLargeEnforcer;

    @Setup(Level.Trial)
    public void setupBuildRoleLinksWithPatternLarge() {
        buildRoleLinksWithPatternLargeEnforcer = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        buildRoleLinksWithPatternLargeEnforcer.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
    }

    @Benchmark
    public void benchmarkBuildRoleLinksWithPatternLarge() {
        buildRoleLinksWithPatternLargeEnforcer.buildRoleLinks();
    }

    private Enforcer buildRoleLinksWithDomainPatternLargeEnforcer;

    @Setup(Level.Trial)
    public void setupBuildRoleLinksWithDomainPatternLarge() {
        buildRoleLinksWithDomainPatternLargeEnforcer = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        buildRoleLinksWithDomainPatternLargeEnforcer.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
    }

    @Benchmark
    public void benchmarkBuildRoleLinksWithDomainPatternLarge() {
        buildRoleLinksWithDomainPatternLargeEnforcer.buildRoleLinks();
    }

    private Enforcer buildRoleLinksWithPatternAndDomainPatternLargeEnforcer;

    @Setup(Level.Trial)
    public void setupBuildRoleLinksWithPatternAndDomainPatternLarge() {
        buildRoleLinksWithPatternAndDomainPatternLargeEnforcer = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        buildRoleLinksWithPatternAndDomainPatternLargeEnforcer.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        buildRoleLinksWithPatternAndDomainPatternLargeEnforcer.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
    }

    @Benchmark
    public void benchmarkBuildRoleLinksWithPatternAndDomainPatternLarge() {
        buildRoleLinksWithPatternAndDomainPatternLargeEnforcer.buildRoleLinks();
    }

    private RoleManager hasLinkWithPatternLargeRm;

    @Setup(Level.Trial)
    public void setupHasLinkWithPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        hasLinkWithPatternLargeRm = e.getRoleManager();
    }

    @Benchmark
    public void benchmarkHasLinkWithPatternLarge() {
        hasLinkWithPatternLargeRm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    private RoleManager hasLinkWithDomainPatternLargeRm;

    @Setup(Level.Trial)
    public void setupHasLinkWithDomainPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        hasLinkWithDomainPatternLargeRm = e.getRoleManager();
    }

    @Benchmark
    public void benchmarkHasLinkWithDomainPatternLarge() {
        hasLinkWithDomainPatternLargeRm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    private RoleManager hasLinkWithPatternAndDomainPatternLargeRm;

    @Setup(Level.Trial)
    public void setupHasLinkWithPatternAndDomainPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        e.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        hasLinkWithPatternAndDomainPatternLargeRm = e.getRoleManager();
    }

    @Benchmark
    public void benchmarkHasLinkWithPatternAndDomainPatternLarge() {
        hasLinkWithPatternAndDomainPatternLargeRm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    @Benchmark
    public void benchmarkConcurrentHasLinkWithMatching(ThreadState state) {
        state.rm.hasLink("alice", "/book/123");
    }

    @State(Scope.Thread)
    public static class ThreadState {
        RoleManager rm;

        @Setup(Level.Trial)
        public void setup() {
            Enforcer e = new Enforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv");
            e.addNamedMatchingFunc("g2", "keyMatch2", BuiltInFunctions::keyMatch2);
            rm = e.getRoleManager();
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(RoleManagerBenchmarkTest.class.getSimpleName())
                .forks(1)
                .warmupIterations(5)
                .measurementIterations(5)
                .build();
        new Runner(opt).run();
    }
}
