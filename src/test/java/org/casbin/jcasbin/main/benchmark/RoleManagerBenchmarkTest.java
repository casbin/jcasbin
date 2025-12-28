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

@BenchmarkMode(Mode.Throughput)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Benchmark)
@OutputTimeUnit(TimeUnit.SECONDS)
public class RoleManagerBenchmarkTest {

    @Benchmark
    public void benchmarkRoleManagerSmall() {
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

        RoleManager rm = e.getRoleManager();

        for (int j = 0; j < 100; j++) {
            rm.hasLink("user501", String.format("group%d", j));
        }
    }

    @Benchmark
    public void benchmarkRoleManagerMedium() {
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

        RoleManager rm = e.getRoleManager();

        for (int j = 0; j < 1000; j++) {
            rm.hasLink("user501", String.format("group%d", j));
        }
    }

    @Benchmark
    public void benchmarkRoleManagerLarge() {
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

        RoleManager rm = e.getRoleManager();

        for (int j = 0; j < 10000; j++) {
            rm.hasLink("user501", String.format("group%d", j));
        }
    }

    @Benchmark
    public void benchmarkBuildRoleLinksWithPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        e.buildRoleLinks();
    }

    @Benchmark
    public void benchmarkBuildRoleLinksWithDomainPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        e.buildRoleLinks();
    }

    @Benchmark
    public void benchmarkBuildRoleLinksWithPatternAndDomainPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        e.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        e.buildRoleLinks();
    }

    @Benchmark
    public void benchmarkHasLinkWithPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        RoleManager rm = e.getRoleManager();
        rm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    @Benchmark
    public void benchmarkHasLinkWithDomainPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        RoleManager rm = e.getRoleManager();
        rm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    @Benchmark
    public void benchmarkHasLinkWithPatternAndDomainPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        e.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        RoleManager rm = e.getRoleManager();
        rm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
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
                .include(RoleManagerBenchmarkTest.class.getName())
                .build();
        new Runner(opt).run();
    }
}
