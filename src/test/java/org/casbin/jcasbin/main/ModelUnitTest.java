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

import static org.casbin.jcasbin.main.TestUtil.testDomainEnforce;
import static org.casbin.jcasbin.main.TestUtil.testEnforce;
import static org.casbin.jcasbin.main.TestUtil.testEnforceWithoutUsers;

import java.util.List;

import org.casbin.jcasbin.rbac.RoleManager;
import org.junit.Test;

public class ModelUnitTest {
    @Test
    public void testBasicModel() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testBasicModelNoPolicy() {
        Enforcer e = new Enforcer("examples/basic_model.conf");

        testEnforce(e, "alice", "data1", "read", false);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", false);
    }

    @Test
    public void testBasicModelWithRoot() {
        Enforcer e = new Enforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
        testEnforce(e, "root", "data1", "read", true);
        testEnforce(e, "root", "data1", "write", true);
        testEnforce(e, "root", "data2", "read", true);
        testEnforce(e, "root", "data2", "write", true);
    }

    @Test
    public void testBasicModelWithRootNoPolicy() {
        Enforcer e = new Enforcer("examples/basic_with_root_model.conf");

        testEnforce(e, "alice", "data1", "read", false);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", false);
        testEnforce(e, "root", "data1", "read", true);
        testEnforce(e, "root", "data1", "write", true);
        testEnforce(e, "root", "data2", "read", true);
        testEnforce(e, "root", "data2", "write", true);
    }

    @Test
    public void testBasicModelWithoutUsers() {
        Enforcer e = new Enforcer("examples/basic_without_users_model.conf", "examples/basic_without_users_policy.csv");

        testEnforceWithoutUsers(e, "data1", "read", true);
        testEnforceWithoutUsers(e, "data1", "write", false);
        testEnforceWithoutUsers(e, "data2", "read", false);
        testEnforceWithoutUsers(e, "data2", "write", true);
    }

    @Test
    public void testBasicModelWithoutResources() {
        Enforcer e = new Enforcer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv");

        testEnforceWithoutUsers(e, "alice", "read", true);
        testEnforceWithoutUsers(e, "alice", "write", false);
        testEnforceWithoutUsers(e, "bob", "read", false);
        testEnforceWithoutUsers(e, "bob", "write", true);
    }

    @Test
    public void testRBACModel() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithResourceRoles() {
        Enforcer e = new Enforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", true);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithDomains() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithDomainsAtRuntime() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf");

        e.addPolicy("admin", "domain1", "data1", "read");
        e.addPolicy("admin", "domain1", "data1", "write");
        e.addPolicy("admin", "domain2", "data2", "read");
        e.addPolicy("admin", "domain2", "data2", "write");

        e.addGroupingPolicy("alice", "admin", "domain1");
        e.addGroupingPolicy("bob", "admin", "domain2");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);

        // Remove all policy rules related to domain1 and data1.
        e.removeFilteredPolicy(1, "domain1", "data1");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);

        // Remove the specified policy rule.
        e.removePolicy("admin", "domain2", "data2", "read");

        testDomainEnforce(e, "alice", "domain1", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "read", false);
        testDomainEnforce(e, "alice", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithDeny() {
        Enforcer e = new Enforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testRBACModelWithOnlyDeny() {
        Enforcer e = new Enforcer("examples/rbac_with_not_deny_model.conf", "examples/rbac_with_deny_policy.csv");

        testEnforce(e, "alice", "data2", "write", false);
    }

    @Test
    public void testRBACModelWithCustomData() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        // You can add custom data to a grouping policy, Casbin will ignore it. It is only
        // meaningful to the caller.
        // This feature can be used to store information like whether "bob" is an end user (so no
        // subject will inherit "bob")
        // For Casbin, it is equivalent to: e.addGroupingPolicy("bob", "data2_admin")
        e.addGroupingPolicy("bob", "data2_admin", "custom_data");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", true);
        testEnforce(e, "bob", "data2", "write", true);

        // You should also take the custom data as a parameter when deleting a grouping policy.
        // e.removeGroupingPolicy("bob", "data2_admin") won't work.
        // Or you can remove it by using removeFilteredGroupingPolicy().
        e.removeGroupingPolicy("bob", "data2_admin", "custom_data");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    class CustomRoleManager implements RoleManager {
        public void clear() {
        }

        public void addLink(String name1, String name2, String... domain) {
        }

        public void deleteLink(String name1, String name2, String... domain) {
        }

        public boolean hasLink(String name1, String name2, String... domain) {
            if (name1.equals("alice") && name2.equals("alice")) {
                return true;
            } else if (name1.equals("alice") && name2.equals("data2_admin")) {
                return true;
            } else if (name1.equals("bob") && name2.equals("bob")) {
                return true;
            }
            return false;
        }

        public List<String> getRoles(String name, String... domain) {
            return null;
        }

        public List<String> getUsers(String name, String... domain) {
            return null;
        }

        public void printRoles() {
        }
    }

    @Test
    public void testRBACModelWithCustomRoleManager() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        e.setRoleManager(new CustomRoleManager());
        e.loadModel();
        e.loadPolicy();

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

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

    @Test
    public void testABACModel() {
        Enforcer e = new Enforcer("examples/abac_model.conf");

        TestResource data1 = new TestResource("data1", "alice");
        TestResource data2 = new TestResource("data2", "bob");

        testEnforce(e, "alice", data1, "read", true);
        testEnforce(e, "alice", data1, "write", true);
        testEnforce(e, "alice", data2, "read", false);
        testEnforce(e, "alice", data2, "write", false);
        testEnforce(e, "bob", data1, "read", false);
        testEnforce(e, "bob", data1, "write", false);
        testEnforce(e, "bob", data2, "read", true);
        testEnforce(e, "bob", data2, "write", true);
    }

    @Test
    public void testKeyMatchModel() {
        Enforcer e = new Enforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv");

        testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource1", "POST", true);
        testEnforce(e, "alice", "/alice_data/resource2", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource2", "POST", false);
        testEnforce(e, "alice", "/bob_data/resource1", "GET", false);
        testEnforce(e, "alice", "/bob_data/resource1", "POST", false);
        testEnforce(e, "alice", "/bob_data/resource2", "GET", false);
        testEnforce(e, "alice", "/bob_data/resource2", "POST", false);

        testEnforce(e, "bob", "/alice_data/resource1", "GET", false);
        testEnforce(e, "bob", "/alice_data/resource1", "POST", false);
        testEnforce(e, "bob", "/alice_data/resource2", "GET", true);
        testEnforce(e, "bob", "/alice_data/resource2", "POST", false);
        testEnforce(e, "bob", "/bob_data/resource1", "GET", false);
        testEnforce(e, "bob", "/bob_data/resource1", "POST", true);
        testEnforce(e, "bob", "/bob_data/resource2", "GET", false);
        testEnforce(e, "bob", "/bob_data/resource2", "POST", true);

        testEnforce(e, "cathy", "/cathy_data", "GET", true);
        testEnforce(e, "cathy", "/cathy_data", "POST", true);
        testEnforce(e, "cathy", "/cathy_data", "DELETE", false);
    }

    @Test
    public void testKeyMatch2Model() {
        Enforcer e = new Enforcer("examples/keymatch2_model.conf", "examples/keymatch2_policy.csv");

        testEnforce(e, "alice", "/alice_data", "GET", false);
        testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
        testEnforce(e, "alice", "/alice_data2/myid", "GET", false);
        testEnforce(e, "alice", "/alice_data2/myid/using/res_id", "GET", true);
    }

    @Test
    public void testIPMatchModel() {
        Enforcer e = new Enforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv");

        testEnforce(e, "192.168.2.123", "data1", "read", true);
        testEnforce(e, "192.168.2.123", "data1", "write", false);
        testEnforce(e, "192.168.2.123", "data2", "read", false);
        testEnforce(e, "192.168.2.123", "data2", "write", false);

        testEnforce(e, "192.168.0.123", "data1", "read", false);
        testEnforce(e, "192.168.0.123", "data1", "write", false);
        testEnforce(e, "192.168.0.123", "data2", "read", false);
        testEnforce(e, "192.168.0.123", "data2", "write", false);

        testEnforce(e, "10.0.0.5", "data1", "read", false);
        testEnforce(e, "10.0.0.5", "data1", "write", false);
        testEnforce(e, "10.0.0.5", "data2", "read", false);
        testEnforce(e, "10.0.0.5", "data2", "write", true);

        testEnforce(e, "192.168.0.1", "data1", "read", false);
        testEnforce(e, "192.168.0.1", "data1", "write", false);
        testEnforce(e, "192.168.0.1", "data2", "read", false);
        testEnforce(e, "192.168.0.1", "data2", "write", false);
    }

    @Test
    public void testPriorityModel() {
        Enforcer e = new Enforcer("examples/priority_model.conf", "examples/priority_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", true);
        testEnforce(e, "bob", "data2", "write", false);
    }

    @Test
    public void testPriorityModelIndeterminate() {
        Enforcer e = new Enforcer("examples/priority_model.conf", "examples/priority_indeterminate_policy.csv");

        testEnforce(e, "alice", "data1", "read", false);
    }
}
