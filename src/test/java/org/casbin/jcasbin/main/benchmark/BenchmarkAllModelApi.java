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

import java.util.Arrays;
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
    private static final String MODEL_PATH = "examples/rbac_model.conf";

    private Enforcer smallEnforcer;
    private Enforcer mediumEnforcer;
    private Enforcer largeEnforcer;

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(org.casbin.jcasbin.main.benchmark.BenchmarkAllModelApi.class.getName())
            .exclude("Pref")
            .exclude("random")
            .build();
        new Runner(opt).run();
    }

    @Setup(Level.Trial)
    public void setup() {
        smallEnforcer = new Enforcer(MODEL_PATH, "", false);
        mediumEnforcer = new Enforcer(MODEL_PATH, "", false);
        largeEnforcer = new Enforcer(MODEL_PATH, "", false);

        for (int i = 0; i < 100; i++) {
            smallEnforcer.addPolicy("user" + i, "data" + i / 10, "read");
        }
        for (int i = 0; i < 1000; i++) {
            mediumEnforcer.addPolicy("user" + i, "data" + i / 10, "read");
        }
        for (int i = 0; i < 10000; i++) {
            largeEnforcer.addPolicy("user" + i, "data" + i / 10, "read");
        }
    }

    @Benchmark
    public void addPolicySmall(AddState state) {
        for (int i = 0; i < 100; i++) {
            int dataIndex = (i * 31 + state.invocationSeed) % 50;
            state.enforcer.addPolicy("user" + i, "data" + dataIndex, "read");
        }
    }

    @Benchmark
    public void addPolicyMedium(AddState state) {
        for (int i = 0; i < 1000; i++) {
            int dataIndex = (i * 31 + state.invocationSeed) % 500;
            state.enforcer.addPolicy("user" + i, "data" + dataIndex, "read");
        }
    }

    @Benchmark
    public void addPolicyLarge(AddState state) {
        for (int i = 0; i < 10000; i++) {
            int dataIndex = (i * 31 + state.invocationSeed) % 5000;
            state.enforcer.addPolicy("user" + i, "data" + dataIndex, "read");
        }
    }


    @Benchmark
    public void hasPolicySmall() {
        for (int i = 0; i < 100; i++) {
            int userIndex = i;
            smallEnforcer.hasPolicy("user" + userIndex, "data" + userIndex / 10, "read");
        }
    }

    @Benchmark
    public void hasPolicyMedium() {
        for (int i = 0; i < 1000; i++) {
            int userIndex = i;
            mediumEnforcer.hasPolicy("user" + userIndex, "data" + userIndex / 10, "read");
        }
    }

    @Benchmark
    public void hasPolicyLarge() {
        for (int i = 0; i < 10000; i++) {
            int userIndex = i;
            largeEnforcer.hasPolicy("user" + userIndex, "data" + userIndex / 10, "read");
        }
    }

    @Benchmark
    public void updatePolicySmall(UpdateStateSmall state) {
        for (int i = 0; i < state.oldRules.size(); i++) {
            state.enforcer.updatePolicy(state.oldRules.get(i), state.newRules.get(i));
        }
    }

    @Benchmark
    public void updatePolicyMedium(UpdateStateMedium state) {
        for (int i = 0; i < state.oldRules.size(); i++) {
            state.enforcer.updatePolicy(state.oldRules.get(i), state.newRules.get(i));
        }
    }

    @Benchmark
    public void updatePolicyLarge(UpdateStateLarge state) {
        for (int i = 0; i < state.oldRules.size(); i++) {
            state.enforcer.updatePolicy(state.oldRules.get(i), state.newRules.get(i));
        }
    }

    @Benchmark
    public void removePolicySmall(RemoveStateSmall state) {
        for (int i = 0; i < state.users.length; i++) {
            state.enforcer.removePolicy(state.users[i], state.data[i], "read");
        }
    }

    @Benchmark
    public void removePolicyMedium(RemoveStateMedium state) {
        for (int i = 0; i < state.users.length; i++) {
            state.enforcer.removePolicy(state.users[i], state.data[i], "read");
        }
    }

    @Benchmark
    public void removePolicyLarge(RemoveStateLarge state) {
        for (int i = 0; i < state.users.length; i++) {
            state.enforcer.removePolicy(state.users[i], state.data[i], "read");
        }
    }

    @State(Scope.Thread)
    public static class AddState {
        private Enforcer enforcer;
        private int invocationSeed;

        @Setup(Level.Trial)
        public void setup() {
            enforcer = new Enforcer(MODEL_PATH, "", false);
        }

        @Setup(Level.Invocation)
        public void reset() {
            enforcer.clearPolicy();
            invocationSeed = invocationSeed * 1103515245 + 12345;
        }
    }

    @State(Scope.Thread)
    public static class UpdateStateSmall {
        private Enforcer enforcer;
        private List<List<String>> oldRules;
        private List<List<String>> newRules;

        @Setup(Level.Trial)
        public void setup() {
            enforcer = new Enforcer(MODEL_PATH, "", false);
        }

        @Setup(Level.Invocation)
        public void reset() {
            enforcer.clearPolicy();
            oldRules = new ArrayList<>(100);
            newRules = new ArrayList<>(100);
            for (int i = 0; i < 100; i++) {
                String user = "user" + i;
                String oldData = "data" + i / 10;
                String newData = "data" + (i / 10 + 1);
                enforcer.addPolicy(user, oldData, "read");
                oldRules.add(Arrays.asList(user, oldData, "read"));
                newRules.add(Arrays.asList(user, newData, "read"));
            }
        }
    }

    @State(Scope.Thread)
    public static class UpdateStateMedium {
        private Enforcer enforcer;
        private List<List<String>> oldRules;
        private List<List<String>> newRules;

        @Setup(Level.Trial)
        public void setup() {
            enforcer = new Enforcer(MODEL_PATH, "", false);
        }

        @Setup(Level.Invocation)
        public void reset() {
            enforcer.clearPolicy();
            oldRules = new ArrayList<>(100);
            newRules = new ArrayList<>(100);
            for (int i = 0; i < 100; i++) {
                int userIndex = i * 10;
                String user = "user" + userIndex;
                String oldData = "data" + userIndex / 10;
                String newData = "data" + (userIndex / 10 + 1);
                enforcer.addPolicy(user, oldData, "read");
                oldRules.add(Arrays.asList(user, oldData, "read"));
                newRules.add(Arrays.asList(user, newData, "read"));
            }
        }
    }

    @State(Scope.Thread)
    public static class UpdateStateLarge {
        private Enforcer enforcer;
        private List<List<String>> oldRules;
        private List<List<String>> newRules;

        @Setup(Level.Trial)
        public void setup() {
            enforcer = new Enforcer(MODEL_PATH, "", false);
        }

        @Setup(Level.Invocation)
        public void reset() {
            enforcer.clearPolicy();
            oldRules = new ArrayList<>(100);
            newRules = new ArrayList<>(100);
            for (int i = 0; i < 100; i++) {
                int userIndex = i * 100;
                String user = "user" + userIndex;
                String oldData = "data" + userIndex / 10;
                String newData = "data" + (userIndex / 10 + 1);
                enforcer.addPolicy(user, oldData, "read");
                oldRules.add(Arrays.asList(user, oldData, "read"));
                newRules.add(Arrays.asList(user, newData, "read"));
            }
        }
    }

    @State(Scope.Thread)
    public static class RemoveStateSmall {
        private Enforcer enforcer;
        private String[] users;
        private String[] data;

        @Setup(Level.Trial)
        public void setup() {
            enforcer = new Enforcer(MODEL_PATH, "", false);
            users = new String[100];
            data = new String[100];
            for (int i = 0; i < 100; i++) {
                users[i] = "user" + i;
                data[i] = "data" + i / 10;
            }
        }

        @Setup(Level.Invocation)
        public void reset() {
            enforcer.clearPolicy();
            for (int i = 0; i < users.length; i++) {
                enforcer.addPolicy(users[i], data[i], "read");
            }
        }
    }

    @State(Scope.Thread)
    public static class RemoveStateMedium {
        private Enforcer enforcer;
        private String[] users;
        private String[] data;

        @Setup(Level.Trial)
        public void setup() {
            enforcer = new Enforcer(MODEL_PATH, "", false);
            users = new String[1000];
            data = new String[1000];
            for (int i = 0; i < 1000; i++) {
                users[i] = "user" + i;
                data[i] = "data" + i / 10;
            }
        }

        @Setup(Level.Invocation)
        public void reset() {
            enforcer.clearPolicy();
            for (int i = 0; i < users.length; i++) {
                enforcer.addPolicy(users[i], data[i], "read");
            }
        }
    }

    @State(Scope.Thread)
    public static class RemoveStateLarge {
        private Enforcer enforcer;
        private String[] users;
        private String[] data;

        @Setup(Level.Trial)
        public void setup() {
            enforcer = new Enforcer(MODEL_PATH, "", false);
            users = new String[10000];
            data = new String[10000];
            for (int i = 0; i < 10000; i++) {
                users[i] = "user" + i;
                data[i] = "data" + i / 10;
            }
        }

        @Setup(Level.Invocation)
        public void reset() {
            enforcer.clearPolicy();
            for (int i = 0; i < users.length; i++) {
                enforcer.addPolicy(users[i], data[i], "read");
            }
        }
    }
}
