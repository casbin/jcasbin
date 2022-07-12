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
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * A Simple and comprehensive Benchmark without info of GC.
 * If you want see more info of result, please use other files in the same directory
 *
 * @author imp2002
 * @date 2022-07-12 8:45
 */

@BenchmarkMode(Mode.AverageTime)
@Warmup(iterations = 3)
@Measurement(iterations = 3)
@Threads(1)
@Fork(1)
@State(value = Scope.Benchmark)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class BenchmarkAllModelApi {
    public static Enforcer smallEnforcer;
    public static Enforcer mediumEnforcer;
    public static Enforcer largeEnforcer;
    public static Enforcer enforcerForAdd;

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(org.casbin.jcasbin.main.benchmark.BenchmarkAllModelApi.class.getName())
            .exclude("Pref")
            .exclude("random")
            .build();
        new Runner(opt).run();
    }

    static {
        smallEnforcer = new Enforcer("examples/rbac_model.conf", "", false);
        mediumEnforcer = new Enforcer("examples/rbac_model.conf", "", false);
        largeEnforcer = new Enforcer("examples/rbac_model.conf", "", false);
        enforcerForAdd = new Enforcer("examples/rbac_model.conf", "", false);

        // 100 roles, 10 resources.
        for (int i = 0; i < 100; i++) {
            smallEnforcer.addPolicy("user" + i, "data" + i / 10, "read");
        }
        // 1000 roles, 100 resources.
        for (int i = 0; i < 1000; i++) {
            mediumEnforcer.addPolicy("user" + i, "data" + i / 10, "read");
        }
        // 10000 roles, 1000 resources.
        for (int i = 0; i < 10000; i++) {
            largeEnforcer.addPolicy("user" + i, "data" + i / 10, "read");
        }
    }

    @Benchmark
    public static void addPolicySmall() {
        for (int i = 0; i < 100; i++) {
            enforcerForAdd.addPolicy("user" + i, "data" + (int) (Math.random() * 50), "read");
        }
    }

    @Benchmark
    public static void addPolicyMedium() {
        for (int i = 0; i < 1000; i++) {
            enforcerForAdd.addPolicy("user" + i, "data" + (int) (Math.random() * 500), "read");
        }
    }

    @Benchmark
    public static void addPolicyLarge() {
        for (int i = 0; i < 10000; i++) {
            enforcerForAdd.addPolicy("user" + i, "data" + (int) (Math.random() * 500), "read");
        }
    }


    @Benchmark
    public static void hasPolicySmall() {
        for (int i = 0; i < 100; i++) {
            smallEnforcer.hasPolicy("user" + (int) (Math.random() * 100), "data" + (int) (Math.random() * 10), "read");
        }
    }

    @Benchmark
    public static void hasPolicyMedium() {
        for (int i = 0; i < 1000; i++) {
            mediumEnforcer.hasPolicy("user" + (int) (Math.random() * 1000), "data" + (int) (Math.random() * 100), "read");
        }
    }

    @Benchmark
    public static void hasPolicyLarge() {
        for (int i = 0; i < 10000; i++) {
            largeEnforcer.hasPolicy("user" + (int) (Math.random() * 10000), "data" + (int) (Math.random() * 1000), "read");
        }
    }

    @Benchmark
    public static void updatePolicySmall() {
        for (int i = 0; i < 100; i++) {
            List<String> oldRule = new ArrayList<>();
            List<String> newRule = new ArrayList<>();
            oldRule.add("user" + (int) (Math.random() * 100));
            oldRule.add("data" + (int) (Math.random() * 10));
            oldRule.add("read");
            newRule.add("user" + (int) (Math.random() * 100));
            newRule.add("data" + (int) (Math.random() * 10));
            newRule.add("read");

            smallEnforcer.updatePolicy(oldRule, newRule);
        }
    }

    @Benchmark
    public static void updatePolicyMedium() {
        for (int i = 0; i < 100; i++) {
            List<String> oldRule = new ArrayList<>();
            List<String> newRule = new ArrayList<>();
            oldRule.add("user" + (int) (Math.random() * 1000));
            oldRule.add("data" + (int) (Math.random() * 100));
            oldRule.add("read");
            newRule.add("user" + (int) (Math.random() * 1000));
            newRule.add("data" + (int) (Math.random() * 100));
            newRule.add("read");

            mediumEnforcer.updatePolicy(oldRule, newRule);
        }
    }

    @Benchmark
    public static void updatePolicyLarge() {
        for (int i = 0; i < 100; i++) {
            List<String> oldRule = new ArrayList<>();
            List<String> newRule = new ArrayList<>();
            oldRule.add("user" + (int) (Math.random() * 10000));
            oldRule.add("data" + (int) (Math.random() * 1000));
            oldRule.add("read");
            newRule.add("user" + (int) (Math.random() * 10000));
            newRule.add("data" + (int) (Math.random() * 1000));
            newRule.add("read");

            largeEnforcer.updatePolicy(oldRule, newRule);
        }
    }

    @Benchmark
    public static void removePolicySmall() {
        for (int i = 0; i < 100; i++) {
            smallEnforcer.removePolicy("user" + (int) (Math.random() * 100), "data" + (int) (Math.random() * 10), "read");
        }
    }

    @Benchmark
    public static void removePolicyMedium() {
        for (int i = 0; i < 1000; i++) {
            mediumEnforcer.removePolicy("user" + (int) (Math.random() * 1000), "data" + (int) (Math.random() * 100), "read");
        }
    }

    @Benchmark
    public static void removePolicyLarge() {
        for (int i = 0; i < 10000; i++) {
            largeEnforcer.removePolicy("user" + (int) (Math.random() * 10000), "data" + (int) (Math.random() * 1000), "read");
        }
    }
}
