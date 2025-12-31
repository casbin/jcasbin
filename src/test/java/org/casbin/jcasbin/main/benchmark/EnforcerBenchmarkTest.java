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

import org.casbin.jcasbin.main.Enforcer;
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
public class EnforcerBenchmarkTest {

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

    public static class TestSubject {
        private String name;
        private int age;

        public TestSubject(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
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

    private static TestSubject newTestSubject(String name, int age) {
        return new TestSubject(name, age);
    }

    @Benchmark
    public void benchmarkRaw() {
        rawEnforce("alice", "data1", "read");
    }

    @Benchmark
    public void benchmarkBasicModel() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        e.enforce("alice", "data1", "read");
    }

    @Benchmark
    public void benchmarkRBACModel() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        e.enforce("alice", "data2", "read");
    }

    @Benchmark
    public void benchmarkRBACModelSmall() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            e.addPolicy(String.format("group%d", i), String.format("data%d", i / 10), "read");
        }

        // 1000 users.
        for (int i = 0; i < 1000; i++) {
            e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i / 10));
        }

        e.enforce("user501", "data9", "read");
    }

    @Benchmark
    public void benchmarkRBACModelMedium() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "");

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

        e.enforce("user5001", "data99", "read");
    }

    @Benchmark
    public void benchmarkRBACModelLarge() {
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

        e.enforce("user50001", "data999", "read");
    }

    @Benchmark
    public void benchmarkRBACModelWithResourceRoles() {
        Enforcer e = new Enforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv");
        e.enforce("alice", "data1", "read");
    }

    @Benchmark
    public void benchmarkRBACModelWithDomains() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");
        e.enforce("alice", "domain1", "data1", "read");
    }

    @Benchmark
    public void benchmarkABACModel() {
        Enforcer e = new Enforcer("examples/abac_model.conf", "");
        TestResource data1 = newTestResource("data1", "alice");
        e.enforce("alice", data1, "read");
    }

    @Benchmark
    public void benchmarkABACRuleModel() {
        Enforcer e = new Enforcer("examples/abac_rule_model.conf", "");
        TestSubject sub = newTestSubject("alice", 18);

        for (int i = 0; i < 1000; i++) {
            e.addPolicy("r.sub.Age > 20", String.format("data%d", i), "read");
        }

        e.enforce(sub, "data100", "read");
    }

    @Benchmark
    public void benchmarkKeyMatchModel() {
        Enforcer e = new Enforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv");
        e.enforce("alice", "/alice_data/resource1", "GET");
    }

    @Benchmark
    public void benchmarkRBACModelWithDeny() {
        Enforcer e = new Enforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv");
        e.enforce("alice", "data1", "read");
    }

    @Benchmark
    public void benchmarkPriorityModel() {
        Enforcer e = new Enforcer("examples/priority_model.conf", "examples/priority_policy.csv");
        e.enforce("alice", "data1", "read");
    }

    @Benchmark
    public void benchmarkRBACModelWithDomainPatternLarge() {
        Enforcer e = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        e.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        e.buildRoleLinks();
        e.enforce("staffUser1001", "/orgs/1/sites/site001", "App001.Module001.Action1001");
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(EnforcerBenchmarkTest.class.getName())
                .build();
        new Runner(opt).run();
    }
}
