// Copyright 2018 The casbin Authors. All Rights Reserved.
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

import com.googlecode.aviator.AviatorEvaluator;
import com.googlecode.aviator.AviatorEvaluatorInstance;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.TestUtil.*;

public class ManagementAPIUnitTest {
    @Test
    public void testGetPolicyAPI() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testGetPolicy(e, asList(
            asList("alice", "data1", "read"),
            asList("bob", "data2", "write"),
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write")));

        testGetFilteredPolicy(e, 0, asList(asList("alice", "data1", "read")), "alice");
        testGetFilteredPolicy(e, 0, asList(asList("bob", "data2", "write")), "bob");
        testGetFilteredPolicy(e, 0, asList(asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")), "data2_admin");
        testGetFilteredPolicy(e, 1, asList(asList("alice", "data1", "read")), "data1");
        testGetFilteredPolicy(e, 1, asList(asList("bob", "data2", "write"), asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")), "data2");
        testGetFilteredPolicy(e, 2, asList(asList("alice", "data1", "read"), asList("data2_admin", "data2", "read")), "read");
        testGetFilteredPolicy(e, 2, asList(asList("bob", "data2", "write"), asList("data2_admin", "data2", "write")), "write");

        testGetFilteredPolicy(e, 0, asList(asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")), "data2_admin", "data2");
        // Note: "" (empty string) in fieldValues means matching all values.
        testGetFilteredPolicy(e, 0, asList(asList("data2_admin", "data2", "read")), "data2_admin", "", "read");
        testGetFilteredPolicy(e, 1, asList(asList("bob", "data2", "write"), asList("data2_admin", "data2", "write")), "data2", "write");

        testHasPolicy(e, asList("alice", "data1", "read"), true);
        testHasPolicy(e, asList("bob", "data2", "write"), true);
        testHasPolicy(e, asList("alice", "data2", "read"), false);
        testHasPolicy(e, asList("bob", "data3", "write"), false);

        testGetGroupingPolicy(e, asList(asList("alice", "data2_admin")));

        testGetFilteredGroupingPolicy(e, 0, asList(asList("alice", "data2_admin")), "alice");
        testGetFilteredGroupingPolicy(e, 0, asList(), "bob");
        testGetFilteredGroupingPolicy(e, 1, asList(), "data1_admin");
        testGetFilteredGroupingPolicy(e, 1, asList(asList("alice", "data2_admin")), "data2_admin");
        // Note: "" (empty string) in fieldValues means matching all values.
        testGetFilteredGroupingPolicy(e, 0, asList(asList("alice", "data2_admin")), "", "data2_admin");

        testHasGroupingPolicy(e, asList("alice", "data2_admin"), true);
        testHasGroupingPolicy(e, asList("bob", "data2_admin"), false);
    }

    @Test
    public void testModifyPolicyAPI() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testGetPolicy(e, asList(
            asList("alice", "data1", "read"),
            asList("bob", "data2", "write"),
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write")));

        e.removePolicy("alice", "data1", "read");
        e.removePolicy("bob", "data2", "write");
        e.removePolicy("alice", "data1", "read");
        e.addPolicy("eve", "data3", "read");
        e.addPolicy("eve", "data3", "read");

        String[][] rules = {
            {"jack", "data4", "read"},
            {"jack", "data4", "read"},
            {"jack", "data4", "read"},
            {"katy", "data4", "write"},
            {"leyo", "data4", "read"},
            {"katy", "data4", "write"},
            {"katy", "data4", "write"},
            {"ham", "data4", "write"},
        };

        e.addPolicies(rules);
        e.addPolicies(rules);

        testGetPolicy(e, asList(
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write"),
            asList("eve", "data3", "read"),
            asList("jack", "data4", "read"),
            asList("katy", "data4", "write"),
            asList("leyo", "data4", "read"),
            asList("ham", "data4", "write")));

        e.removePolicies(rules);
        e.removePolicies(rules);

        List<String> namedPolicy = asList("eve", "data3", "read");
        e.removeNamedPolicy("p", namedPolicy);
        e.addNamedPolicy("p", namedPolicy);

        testGetPolicy(e, asList(
            asList("data2_admin", "data2", "read"),
            asList("data2_admin", "data2", "write"),
            asList("eve", "data3", "read")));

        e.removeFilteredPolicy(1, "data2");

        testGetPolicy(e, asList(asList("eve", "data3", "read")));

        e.updatePolicy(asList("eve", "data3", "read"), asList("eve", "data2", "read"));
        testGetPolicy(e, asList(asList("eve", "data2", "read")));

        e.updateNamedPolicy("p", asList("eve", "data2", "read"), asList("eve", "data4", "read"));
        testGetPolicy(e, asList(asList("eve", "data4", "read")));
    }

    @Test
    public void testModifyGroupingPolicyAPI() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testGetRoles(e, "alice", asList("data2_admin"));
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList());
        testGetRoles(e, "non_exist", asList());

        e.removeGroupingPolicy("alice", "data2_admin");
        e.addGroupingPolicy("bob", "data1_admin");
        e.addGroupingPolicy("eve", "data3_admin");

        String[][] groupingRules = {
            {"ham", "data4_admin"},
            {"jack", "data5_admin"}
        };

        e.addGroupingPolicies(groupingRules);
        testGetRoles(e, "ham", asList("data4_admin"));
        testGetRoles(e, "jack", asList("data5_admin"));
        e.removeGroupingPolicies(groupingRules);

        List<String> namedGroupingPolicy = asList("alice", "data2_admin");
        testGetRoles(e, "alice", asList());
        e.addNamedGroupingPolicy("g", namedGroupingPolicy);
        testGetRoles(e, "alice", asList("data2_admin"));
        e.removeNamedGroupingPolicy("g", namedGroupingPolicy);

        e.addNamedGroupingPolicies("g", groupingRules);
        e.addNamedGroupingPolicies("g", groupingRules);
        testGetRoles(e, "ham", asList("data4_admin"));
        testGetRoles(e, "jack", asList("data5_admin"));
        e.removeNamedGroupingPolicies("g", groupingRules);
        e.removeNamedGroupingPolicies("g", groupingRules);

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList("data1_admin"));
        testGetRoles(e, "eve", asList("data3_admin"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList("bob"));
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin", asList("eve"));

        e.removeFilteredGroupingPolicy(0, "bob");

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList("data3_admin"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList());
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin", asList("eve"));

        e.updateGroupingPolicy(asList("eve", "data3_admin"), asList("eve", "data3_admin_update"));

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList("data3_admin_update"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList());
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin_update", asList("eve"));

        e.updateNamedGroupingPolicy("g", asList("eve", "data3_admin_update"), asList("eve", "data3_admin"));

        testGetRoles(e, "alice", asList());
        testGetRoles(e, "bob", asList());
        testGetRoles(e, "eve", asList("data3_admin"));
        testGetRoles(e, "non_exist", asList());

        testGetUsers(e, "data1_admin", asList());
        testGetUsers(e, "data2_admin", asList());
        testGetUsers(e, "data3_admin", asList("eve"));
    }

    @Test
    public void should_throwsNullPointException_when_setAviatorEvaluator_given_nullInstance() {
        // given
        AviatorEvaluatorInstance instance = null;
        Enforcer enforcer = new Enforcer();
        // when
        Assert.assertThrows("The aviator evaluator cannot be null.", NullPointerException.class,
            () -> enforcer.setAviatorEvaluator(instance));
    }

    @Test
    public void should_true_when_setAviatorEvaluator_given_customInstance() {
        // given
        AviatorEvaluatorInstance instance = AviatorEvaluator.newInstance();
        Enforcer enforcer = new Enforcer();
        // when
        enforcer.setAviatorEvaluator(instance);
        // then
        Assert.assertEquals(instance, enforcer.getAviatorEval());
    }

}
