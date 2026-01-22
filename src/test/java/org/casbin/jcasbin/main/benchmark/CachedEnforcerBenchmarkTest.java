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
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

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

    @Test
    public void benchmarkCachedRaw() {
        BenchmarkUtil.runBenchmark("Cached Raw", () -> {
            rawEnforce("alice", "data1", "read");
        });
    }

    @Test
    public void benchmarkCachedBasicModel() {
        BenchmarkUtil.runBenchmark("Cached Basic Model", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
            e.enforce("alice", "data1", "read");
        });
    }

    @Test
    public void benchmarkCachedRBACModel() {
        BenchmarkUtil.runBenchmark("Cached RBAC Model", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
            e.enforce("alice", "data2", "read");
        });
    }

    @Test
    public void benchmarkCachedRBACModelSmall() {
        BenchmarkUtil.runBenchmark("Cached RBAC Model Small", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/rbac_model.conf", "");

            // 100 roles, 10 resources.
            for (int i = 0; i < 100; i++) {
                e.addPolicy(String.format("group%d", i), String.format("data%d", i / 10), "read");
            }

            // 1000 users.
            for (int i = 0; i < 1000; i++) {
                e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i / 10));
            }

            e.enforce("user501", "data9", "read");
        });
    }

    @Test
    public void benchmarkCachedRBACModelMedium() {
        BenchmarkUtil.runBenchmark("Cached RBAC Model Medium", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/rbac_model.conf", "");

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

            e.enforce("user5001", "data150", "read");
        });
    }

    @Test
    public void benchmarkCachedRBACModelLarge() {
        BenchmarkUtil.runBenchmark("Cached RBAC Model Large", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/rbac_model.conf", "");

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

            e.enforce("user50001", "data1500", "read");
        });
    }

    @Test
    public void benchmarkCachedRBACModelWithResourceRoles() {
        BenchmarkUtil.runBenchmark("Cached RBAC Model With Resource Roles", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv");
            e.enforce("alice", "data1", "read");
        });
    }

    @Test
    public void benchmarkCachedRBACModelWithDomains() {
        BenchmarkUtil.runBenchmark("Cached RBAC Model With Domains", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");
            e.enforce("alice", "domain1", "data1", "read");
        });
    }

    @Test
    public void benchmarkCachedABACModel() {
        BenchmarkUtil.runBenchmark("Cached ABAC Model", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/abac_model.conf", "");
            TestResource data1 = newTestResource("data1", "alice");
            e.enforce("alice", data1, "read");
        });
    }

    @Test
    public void benchmarkCachedKeyMatchModel() {
        BenchmarkUtil.runBenchmark("Cached KeyMatch Model", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv");
            e.enforce("alice", "/alice_data/resource1", "GET");
        });
    }

    @Test
    public void benchmarkCachedRBACModelWithDeny() {
        BenchmarkUtil.runBenchmark("Cached RBAC Model With Deny", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv");
            e.enforce("alice", "data1", "read");
        });
    }

    @Test
    public void benchmarkCachedPriorityModel() {
        BenchmarkUtil.runBenchmark("Cached Priority Model", () -> {
            CachedEnforcer e = new CachedEnforcer("examples/priority_model.conf", "examples/priority_policy.csv");
            e.enforce("alice", "data1", "read");
        });
    }

    @Test
    public void benchmarkCachedRBACModelMediumParallel() {
        CachedEnforcer e = new CachedEnforcer("examples/rbac_model.conf", "");

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

        BenchmarkUtil.runBenchmark("Cached RBAC Model Medium Parallel", () -> {
            e.enforce("user5001", "data150", "read");
        });
    }
}
