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
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ManagementApiBenchmarkTest {

    private Random random = new Random();

    @Test
    public void benchmarkHasPolicySmall() {
        BenchmarkUtil.runBenchmark("HasPolicy Small", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 100 roles, 10 resources.
            for (int i = 0; i < 100; i++) {
                e.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
            }

            e.hasPolicy(String.format("user%d", random.nextInt(100)), String.format("data%d", random.nextInt(100) / 10), "read");
        });
    }

    @Test
    public void benchmarkHasPolicyMedium() {
        BenchmarkUtil.runBenchmark("HasPolicy Medium", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 1000 roles, 100 resources.
            List<List<String>> pPolicies = new ArrayList<>();
            for (int i = 0; i < 1000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("user%d", i));
                policy.add(String.format("data%d", i / 10));
                policy.add("read");
                pPolicies.add(policy);
            }
            e.addPolicies(pPolicies);

            e.hasPolicy(String.format("user%d", random.nextInt(1000)), String.format("data%d", random.nextInt(1000) / 10), "read");
        });
    }

    @Test
    public void benchmarkHasPolicyLarge() {
        BenchmarkUtil.runBenchmark("HasPolicy Large", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 10000 roles, 1000 resources.
            List<List<String>> pPolicies = new ArrayList<>();
            for (int i = 0; i < 10000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("user%d", i));
                policy.add(String.format("data%d", i / 10));
                policy.add("read");
                pPolicies.add(policy);
            }
            e.addPolicies(pPolicies);

            e.hasPolicy(String.format("user%d", random.nextInt(10000)), String.format("data%d", random.nextInt(10000) / 10), "read");
        });
    }

    @Test
    public void benchmarkAddPolicySmall() {
        BenchmarkUtil.runBenchmark("AddPolicy Small", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 100 roles, 10 resources.
            for (int i = 0; i < 100; i++) {
                e.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
            }

            e.addPolicy(String.format("user%d", random.nextInt(100) + 100), String.format("data%d", (random.nextInt(100) + 100) / 10), "read");
        });
    }

    @Test
    public void benchmarkAddPolicyMedium() {
        BenchmarkUtil.runBenchmark("AddPolicy Medium", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 1000 roles, 100 resources.
            List<List<String>> pPolicies = new ArrayList<>();
            for (int i = 0; i < 1000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("user%d", i));
                policy.add(String.format("data%d", i / 10));
                policy.add("read");
                pPolicies.add(policy);
            }
            e.addPolicies(pPolicies);

            e.addPolicy(String.format("user%d", random.nextInt(1000) + 1000), String.format("data%d", (random.nextInt(1000) + 1000) / 10), "read");
        });
    }

    @Test
    public void benchmarkAddPolicyLarge() {
        BenchmarkUtil.runBenchmark("AddPolicy Large", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 10000 roles, 1000 resources.
            List<List<String>> pPolicies = new ArrayList<>();
            for (int i = 0; i < 10000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("user%d", i));
                policy.add(String.format("data%d", i / 10));
                policy.add("read");
                pPolicies.add(policy);
            }
            e.addPolicies(pPolicies);

            e.addPolicy(String.format("user%d", random.nextInt(10000) + 10000), String.format("data%d", (random.nextInt(10000) + 10000) / 10), "read");
        });
    }

    @Test
    public void benchmarkRemovePolicySmall() {
        BenchmarkUtil.runBenchmark("RemovePolicy Small", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 100 roles, 10 resources.
            for (int i = 0; i < 100; i++) {
                e.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
            }

            e.removePolicy(String.format("user%d", random.nextInt(100)), String.format("data%d", random.nextInt(100) / 10), "read");
        });
    }

    @Test
    public void benchmarkRemovePolicyMedium() {
        BenchmarkUtil.runBenchmark("RemovePolicy Medium", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 1000 roles, 100 resources.
            List<List<String>> pPolicies = new ArrayList<>();
            for (int i = 0; i < 1000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("user%d", i));
                policy.add(String.format("data%d", i / 10));
                policy.add("read");
                pPolicies.add(policy);
            }
            e.addPolicies(pPolicies);

            e.removePolicy(String.format("user%d", random.nextInt(1000)), String.format("data%d", random.nextInt(1000) / 10), "read");
        });
    }

    @Test
    public void benchmarkRemovePolicyLarge() {
        BenchmarkUtil.runBenchmark("RemovePolicy Large", () -> {
            Enforcer e = new Enforcer("examples/basic_model.conf", "");

            // 10000 roles, 1000 resources.
            List<List<String>> pPolicies = new ArrayList<>();
            for (int i = 0; i < 10000; i++) {
                List<String> policy = new ArrayList<>();
                policy.add(String.format("user%d", i));
                policy.add(String.format("data%d", i / 10));
                policy.add("read");
                pPolicies.add(policy);
            }
            e.addPolicies(pPolicies);

            e.removePolicy(String.format("user%d", random.nextInt(10000)), String.format("data%d", random.nextInt(10000) / 10), "read");
        });
    }
}
