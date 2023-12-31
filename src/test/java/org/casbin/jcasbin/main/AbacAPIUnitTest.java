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

package org.casbin.jcasbin.main;

import org.casbin.jcasbin.util.Util;
import org.junit.Test;
import java.util.Map;
import java.util.HashMap;

import static org.casbin.jcasbin.main.TestUtil.testDomainEnforce;
import static org.casbin.jcasbin.main.TestUtil.testEnforce;

public class AbacAPIUnitTest {
    @Test
    public void testEval() {
        Enforcer e = new Enforcer("examples/abac_rule_model.conf", "examples/abac_rule_policy.csv");
        TestEvalRule alice = new TestEvalRule("alice", 18);
        // rule with attribute not exist in object will return false, then check the following policy of ACL
        testEnforce(e, alice, "/data0", "read", false);
        testEnforce(e, alice, "/data1", "read", false);
        testEnforce(e, alice, "/data1", "write", false);
        alice.setAge(19);
        testEnforce(e, alice, "/data1", "read", true);
        testEnforce(e, alice, "/data1", "write", false);
        alice.setAge(25);
        testEnforce(e, alice, "/data1", "read", false);
        testEnforce(e, alice, "/data1", "write", false);
        testEnforce(e, alice, "/data2", "read", false);
        testEnforce(e, alice, "/data2", "write", true);
        alice.setAge(60);
        testEnforce(e, alice, "/data2", "read", false);
        testEnforce(e, alice, "/data2", "write", false);
    }

    @Test
    public void testEvalWithDomain() {
        Enforcer e = new Enforcer("examples/abac_rule_with_domains_model.conf", "examples/abac_rule_with_domains_policy.csv");
        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain2", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain1", "data2", "read", false);
        testDomainEnforce(e, "bob", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
    }

    @Test
    public void testABACMapRequest() {
        Enforcer e = new Enforcer("examples/abac_rule_map_model.conf");

        Map<String, Object> data1 = new HashMap<>();
        data1.put("Name", "data1");
        data1.put("Owner", "alice");

        Map<String, Object> data2 = new HashMap<>();
        data2.put("Name", "data2");
        data2.put("Owner", "bob");

        testEnforce(e, "alice", data1, "read", true);
        testEnforce(e, "alice", data1, "write", true);
        testEnforce(e, "alice", data2, "read", false);
        testEnforce(e, "alice", data2, "write", false);
        testEnforce(e, "bob", data1, "read", false);
        testEnforce(e, "bob", data1, "write", false);
        testEnforce(e, "bob", data2, "read", true);
        testEnforce(e, "bob", data2, "write", true);
    }

    public static class TestEvalRule {
        private String name;
        private int age;

        TestEvalRule(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }
    }
}
