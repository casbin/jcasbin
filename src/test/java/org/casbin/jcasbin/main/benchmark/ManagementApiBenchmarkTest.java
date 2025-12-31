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
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Benchmark)
@OutputTimeUnit(TimeUnit.SECONDS)
public class ManagementApiBenchmarkTest {

    private Random random = new Random();

    @Benchmark
    public void benchmarkHasPolicySmall() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            e.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
        }

        e.hasPolicy(String.format("user%d", random.nextInt(100)), String.format("data%d", random.nextInt(100) / 10), "read");
    }

    @Benchmark
    public void benchmarkHasPolicyMedium() {
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
    }

    @Benchmark
    public void benchmarkHasPolicyLarge() {
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
    }

    @Benchmark
    public void benchmarkAddPolicySmall() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            e.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
        }

        e.addPolicy(String.format("user%d", random.nextInt(100) + 100), String.format("data%d", (random.nextInt(100) + 100) / 10), "read");
    }

    @Benchmark
    public void benchmarkAddPolicyMedium() {
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
    }

    @Benchmark
    public void benchmarkAddPolicyLarge() {
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
    }

    @Benchmark
    public void benchmarkRemovePolicySmall() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            e.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
        }

        e.removePolicy(String.format("user%d", random.nextInt(100)), String.format("data%d", random.nextInt(100) / 10), "read");
    }

    @Benchmark
    public void benchmarkRemovePolicyMedium() {
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
    }

    @Benchmark
    public void benchmarkRemovePolicyLarge() {
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
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(ManagementApiBenchmarkTest.class.getName())
                .build();
        new Runner(opt).run();
    }
}
