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

@BenchmarkMode({Mode.Throughput, Mode.AverageTime})
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class ManagementApiBenchmarkTest {

    private Random random;

    @Setup(Level.Trial)
    public void setupRandom() {
        random = new Random();
    }

    private Enforcer hasPolicySmallEnforcer;

    @Setup(Level.Trial)
    public void setupHasPolicySmall() {
        hasPolicySmallEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            hasPolicySmallEnforcer.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
        }
    }

    @Benchmark
    public void benchmarkHasPolicySmall() {
        hasPolicySmallEnforcer.hasPolicy(String.format("user%d", random.nextInt(100)), String.format("data%d", random.nextInt(100) / 10), "read");
    }

    private Enforcer hasPolicyMediumEnforcer;

    @Setup(Level.Trial)
    public void setupHasPolicyMedium() {
        hasPolicyMediumEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 1000 roles, 100 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        hasPolicyMediumEnforcer.addPolicies(pPolicies);
    }

    @Benchmark
    public void benchmarkHasPolicyMedium() {
        hasPolicyMediumEnforcer.hasPolicy(String.format("user%d", random.nextInt(1000)), String.format("data%d", random.nextInt(1000) / 10), "read");
    }

    private Enforcer hasPolicyLargeEnforcer;

    @Setup(Level.Trial)
    public void setupHasPolicyLarge() {
        hasPolicyLargeEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 10000 roles, 1000 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        hasPolicyLargeEnforcer.addPolicies(pPolicies);
    }

    @Benchmark
    public void benchmarkHasPolicyLarge() {
        hasPolicyLargeEnforcer.hasPolicy(String.format("user%d", random.nextInt(10000)), String.format("data%d", random.nextInt(10000) / 10), "read");
    }

    private Enforcer addPolicySmallEnforcer;

    @Setup(Level.Trial)
    public void setupAddPolicySmall() {
        addPolicySmallEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            addPolicySmallEnforcer.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
        }
    }

    @Benchmark
    public void benchmarkAddPolicySmall() {
        addPolicySmallEnforcer.addPolicy(String.format("user%d", random.nextInt(100) + 100), String.format("data%d", (random.nextInt(100) + 100) / 10), "read");
    }

    private Enforcer addPolicyMediumEnforcer;

    @Setup(Level.Trial)
    public void setupAddPolicyMedium() {
        addPolicyMediumEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 1000 roles, 100 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        addPolicyMediumEnforcer.addPolicies(pPolicies);
    }

    @Benchmark
    public void benchmarkAddPolicyMedium() {
        addPolicyMediumEnforcer.addPolicy(String.format("user%d", random.nextInt(1000) + 1000), String.format("data%d", (random.nextInt(1000) + 1000) / 10), "read");
    }

    private Enforcer addPolicyLargeEnforcer;

    @Setup(Level.Trial)
    public void setupAddPolicyLarge() {
        addPolicyLargeEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 10000 roles, 1000 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        addPolicyLargeEnforcer.addPolicies(pPolicies);
    }

    @Benchmark
    public void benchmarkAddPolicyLarge() {
        addPolicyLargeEnforcer.addPolicy(String.format("user%d", random.nextInt(10000) + 10000), String.format("data%d", (random.nextInt(10000) + 10000) / 10), "read");
    }

    private Enforcer removePolicySmallEnforcer;

    @Setup(Level.Trial)
    public void setupRemovePolicySmall() {
        removePolicySmallEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            removePolicySmallEnforcer.addPolicy(String.format("user%d", i), String.format("data%d", i / 10), "read");
        }
    }

    @Benchmark
    public void benchmarkRemovePolicySmall() {
        removePolicySmallEnforcer.removePolicy(String.format("user%d", random.nextInt(100)), String.format("data%d", random.nextInt(100) / 10), "read");
    }

    private Enforcer removePolicyMediumEnforcer;

    @Setup(Level.Trial)
    public void setupRemovePolicyMedium() {
        removePolicyMediumEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 1000 roles, 100 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        removePolicyMediumEnforcer.addPolicies(pPolicies);
    }

    @Benchmark
    public void benchmarkRemovePolicyMedium() {
        removePolicyMediumEnforcer.removePolicy(String.format("user%d", random.nextInt(1000)), String.format("data%d", random.nextInt(1000) / 10), "read");
    }

    private Enforcer removePolicyLargeEnforcer;

    @Setup(Level.Trial)
    public void setupRemovePolicyLarge() {
        removePolicyLargeEnforcer = new Enforcer("examples/basic_model.conf", "");

        // 10000 roles, 1000 resources.
        List<List<String>> pPolicies = new ArrayList<>();
        for (int i = 0; i < 10000; i++) {
            List<String> policy = new ArrayList<>();
            policy.add(String.format("user%d", i));
            policy.add(String.format("data%d", i / 10));
            policy.add("read");
            pPolicies.add(policy);
        }
        removePolicyLargeEnforcer.addPolicies(pPolicies);
    }

    @Benchmark
    public void benchmarkRemovePolicyLarge() {
        removePolicyLargeEnforcer.removePolicy(String.format("user%d", random.nextInt(10000)), String.format("data%d", random.nextInt(10000) / 10), "read");
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(ManagementApiBenchmarkTest.class.getSimpleName())
                .forks(1)
                .warmupIterations(5)
                .measurementIterations(5)
                .build();
        new Runner(opt).run();
    }
}
