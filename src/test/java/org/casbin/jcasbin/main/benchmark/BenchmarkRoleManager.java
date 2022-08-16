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

import java.util.concurrent.TimeUnit;

/**
 * @author Yixiang Zhao (@seriouszyx)
 **/
@BenchmarkMode(Mode.AverageTime)
@Warmup(iterations = 3)
@Measurement(iterations = 3)
@Threads(1)
@Fork(1)
@State(value = Scope.Benchmark)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class BenchmarkRoleManager {

    public static Enforcer smallEnforcer;
    public static Enforcer mediumEnforcer;
    public static Enforcer largeEnforcer;
    public static Enforcer buildRoleLinksWithPattern;
    public static Enforcer buildRoleLinksWithDomainPattern;
    public static Enforcer buildRoleLinksWithPatternAndDomainPattern;
    public static Enforcer hasLinkWithPattern;
    public static Enforcer hasLinkWithDomainPattern;
    public static Enforcer hasLinkWithPatternAndDomainPattern;

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(org.casbin.jcasbin.main.benchmark.BenchmarkRoleManager.class.getName())
            .exclude("Pref")
            .exclude("random")
            .build();
        new Runner(opt).run();
    }

    @Benchmark
    public static void roleManagerSmall() {
        RoleManager rm = smallEnforcer.getRoleManager();
        for (int i = 0; i < 100; i++) {
            rm.hasLink("user501", "group" + i);
        }
    }

    @Benchmark
    public static void roleManagerMedium() {
        RoleManager rm = mediumEnforcer.getRoleManager();
        for (int i = 0; i < 1000; i++) {
            rm.hasLink("user501", "group" + i);
        }
    }

    @Benchmark
    public static void roleManagerLarge() {
        RoleManager rm = largeEnforcer.getRoleManager();
        for (int i = 0; i < 10000; i++) {
            rm.hasLink("user501", "group" + i);
        }
    }

    @Benchmark
    public static void buildRoleLinksWithPatternLarge() {
        buildRoleLinksWithPattern.buildRoleLinks();
    }

    @Benchmark
    public static void buildRoleLinksWithDomainPatternLarge() {
        buildRoleLinksWithDomainPattern.buildRoleLinks();
    }

    @Benchmark
    public static void buildRoleLinksWithPatternAndDomainPatternLarge() {
        buildRoleLinksWithPatternAndDomainPattern.buildRoleLinks();
    }

    @Benchmark
    public static void hasLinkWithPatternLarge() {
        RoleManager rm = hasLinkWithPattern.getRoleManager();
        rm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    @Benchmark
    public static void hasLinkWithDomainPatternLarge() {
        RoleManager rm = hasLinkWithDomainPattern.getRoleManager();
        rm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    @Benchmark
    public static void hasLinkWithPatternAndDomainPatternLarge() {
        RoleManager rm = hasLinkWithPatternAndDomainPattern.getRoleManager();
        rm.hasLink("staffUser1001", "staff001", "/orgs/1/sites/site001");
    }

    static {
        smallEnforcer = initEnforcer(100, 1000);
        mediumEnforcer = initEnforcer(1000, 10000);
        largeEnforcer = initEnforcer(10000, 100000);

        buildRoleLinksWithPattern = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        buildRoleLinksWithPattern.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);

        buildRoleLinksWithDomainPattern = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        buildRoleLinksWithDomainPattern.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);

        buildRoleLinksWithPatternAndDomainPattern = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        buildRoleLinksWithPatternAndDomainPattern.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        buildRoleLinksWithPatternAndDomainPattern.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);

        hasLinkWithPattern = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        hasLinkWithPattern.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);

        hasLinkWithDomainPattern = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        hasLinkWithDomainPattern.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);

        hasLinkWithPatternAndDomainPattern = new Enforcer("examples/performance/rbac_with_pattern_large_scale_model.conf", "examples/performance/rbac_with_pattern_large_scale_policy.csv");
        hasLinkWithPatternAndDomainPattern.addNamedMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
        hasLinkWithPatternAndDomainPattern.addNamedDomainMatchingFunc("g", "", BuiltInFunctions::keyMatch4);
    }

    static Enforcer initEnforcer(int roleNum, int userNum) {
        Enforcer enforcer = new Enforcer("examples/rbac_model.conf", "", false);
        enforcer.enableAutoBuildRoleLinks(false);
        // roleNum roles, roleNum/10 resources.
        for (int i = 0; i < roleNum; i++) {
            enforcer.addPolicy("group" + i, "data" + i / 10, "read");
        }
        // userNum users.
        for (int i = 0; i < userNum; i++) {
            enforcer.addGroupingPolicy("user" + i, "group" + i / 10);
        }
        return enforcer;
    }
}
