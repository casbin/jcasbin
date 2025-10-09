// Copyright 2024 The casbin Authors. All Rights Reserved.
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

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.TestUtil.*;

/**
 * Test for addNamedGroupingPoliciesEx method implementation
 */
public class AddNamedGroupingPoliciesExTest {

    @Test
    public void testAddNamedGroupingPoliciesEx() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        // Test basic functionality
        String[][] rules = {
            {"alice", "admin"},
            {"bob", "user"},
            {"charlie", "moderator"}
        };

        // Add rules for the first time - should succeed
        Assert.assertTrue(e.addNamedGroupingPoliciesEx("g", rules));

        // Verify roles are added correctly
        testGetRoles(e, "alice", asList("data2_admin", "admin"));
        testGetRoles(e, "bob", asList("user"));
        testGetRoles(e, "charlie", asList("moderator"));

        // Test Ex behavior - add some duplicate and some new rules
        String[][] mixedRules = {
            {"alice", "admin"},      // duplicate - should be ignored
            {"bob", "user"},         // duplicate - should be ignored
            {"david", "guest"},      // new rule - should be added
            {"eve", "supervisor"}    // new rule - should be added
        };

        // addNamedGroupingPoliciesEx should succeed even with duplicates
        Assert.assertTrue(e.addNamedGroupingPoliciesEx("g", mixedRules));

        // Verify only new rules were added
        testGetRoles(e, "alice", asList("data2_admin", "admin")); // no duplicates
        testGetRoles(e, "bob", asList("user"));                   // no duplicates
        testGetRoles(e, "david", asList("guest"));                // new rule added
        testGetRoles(e, "eve", asList("supervisor"));             // new rule added

        // Test with List<List<String>> version
        List<List<String>> listRules = asList(
            asList("alice", "admin"),     // duplicate
            asList("frank", "editor")     // new
        );

        Assert.assertTrue(e.addNamedGroupingPoliciesEx("g", listRules));
        testGetRoles(e, "alice", asList("data2_admin", "admin")); // no duplicates
        testGetRoles(e, "frank", asList("editor"));               // new rule added
    }

    @Test
    public void testAddGroupingPoliciesEx() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        // Test basic functionality with default "g" ptype
        String[][] rules = {
            {"alice", "admin"},
            {"bob", "user"}
        };

        Assert.assertTrue(e.addGroupingPoliciesEx(rules));
        testGetRoles(e, "alice", asList("data2_admin", "admin"));
        testGetRoles(e, "bob", asList("user"));

        // Test with duplicates
        String[][] duplicateRules = {
            {"alice", "admin"},    // duplicate
            {"charlie", "guest"}   // new
        };

        Assert.assertTrue(e.addGroupingPoliciesEx(duplicateRules));
        testGetRoles(e, "alice", asList("data2_admin", "admin")); // no duplicates
        testGetRoles(e, "charlie", asList("guest"));              // new rule added
    }

    @Test
    public void testSyncedAddNamedGroupingPoliciesEx() {
        SyncedEnforcer e = new SyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        String[][] rules = {
            {"alice", "admin"},
            {"bob", "user"}
        };

        Assert.assertTrue(e.addNamedGroupingPoliciesEx("g", rules));
        testGetRoles(e, "alice", asList("data2_admin", "admin"));
        testGetRoles(e, "bob", asList("user"));

        // Test with duplicates
        String[][] duplicateRules = {
            {"alice", "admin"},    // duplicate
            {"charlie", "guest"}   // new
        };

        Assert.assertTrue(e.addNamedGroupingPoliciesEx("g", duplicateRules));
        testGetRoles(e, "alice", asList("data2_admin", "admin")); // no duplicates
        testGetRoles(e, "charlie", asList("guest"));              // new rule added
    }
}
