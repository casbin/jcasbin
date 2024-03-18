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

import org.junit.Test;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.TestUtil.*;

public class RbacAPIWithDomainsUnitTest {
    @Test
    public void testRoleAPIWithDomains() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");

        testGetRolesInDomain(e, "alice", "domain1", asList("admin"));
        testGetRolesInDomain(e, "bob", "domain1", asList());
        testGetRolesInDomain(e, "admin", "domain1", asList());
        testGetRolesInDomain(e, "non_exist", "domain1", asList());

        testGetRolesInDomain(e, "alice", "domain2", asList());
        testGetRolesInDomain(e, "bob", "domain2", asList("admin"));
        testGetRolesInDomain(e, "admin", "domain2", asList());
        testGetRolesInDomain(e, "non_exist", "domain2", asList());

        e.deleteRoleForUserInDomain("alice", "admin", "domain1");
        e.addRoleForUserInDomain("bob", "admin", "domain1");

        testGetRolesInDomain(e, "alice", "domain1", asList());
        testGetRolesInDomain(e, "bob", "domain1", asList("admin"));
        testGetRolesInDomain(e, "admin", "domain1", asList());
        testGetRolesInDomain(e, "non_exist", "domain1", asList());

        testGetRolesInDomain(e, "alice", "domain2", asList());
        testGetRolesInDomain(e, "bob", "domain2", asList("admin"));
        testGetRolesInDomain(e, "admin", "domain2", asList());
        testGetRolesInDomain(e, "non_exist", "domain2", asList());
    }

    @Test
    public void testUserAPIWithDomains() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");

        testGetUsersInDomain(e, "alice", "domain1", asList());
        testGetUsersInDomain(e, "bob", "domain1", asList());
        testGetUsersInDomain(e, "admin", "domain1", asList("alice"));
        testGetUsersInDomain(e, "non_exist", "domain1", asList());

        testGetUsersInDomain(e, "alice", "domain2", asList());
        testGetUsersInDomain(e, "bob", "domain2", asList());
        testGetUsersInDomain(e, "admin", "domain2", asList("bob"));
        testGetUsersInDomain(e, "non_exist", "domain2", asList());

        e.deleteRoleForUserInDomain("alice", "admin", "domain1");
        e.addRoleForUserInDomain("alice", "admin", "domain2");
        e.addRoleForUserInDomain("bob", "admin", "domain1");

        testGetUsersInDomain(e, "alice", "domain1", asList());
        testGetUsersInDomain(e, "bob", "domain1", asList());
        testGetUsersInDomain(e, "admin", "domain1", asList("bob"));
        testGetUsersInDomain(e, "non_exist", "domain1", asList());

        testGetUsersInDomain(e, "alice", "domain2", asList());
        testGetUsersInDomain(e, "bob", "domain2", asList());
        testGetUsersInDomain(e, "admin", "domain2", asList("bob", "alice"));
        testGetUsersInDomain(e, "non_exist", "domain2", asList());
    }

    @Test
    public void testPermissionAPIInDomain() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");

        testGetPermissionsInDomain(e, "alice", "domain1", asList());
        testGetPermissionsInDomain(e, "bob", "domain1", asList());
        testGetPermissionsInDomain(e, "admin", "domain1", asList(asList("admin", "domain1", "data1", "read"), asList("admin", "domain1", "data1", "write")));
        testGetPermissionsInDomain(e, "non_exist", "domain1", asList());

        testGetPermissionsInDomain(e, "alice", "domain2", asList());
        testGetPermissionsInDomain(e, "bob", "domain2", asList());
        testGetPermissionsInDomain(e, "admin", "domain2", asList(asList("admin", "domain2", "data2", "read"), asList("admin", "domain2", "data2", "write")));
        testGetPermissionsInDomain(e, "non_exist", "domain2", asList());
    }

    @Test
    public void testImplicitPermissionAPIInDomain() {
        Enforcer e = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");

        testGetImplicitPermissionsInDomain(e, "alice", "domain1", asList(asList("admin", "domain1", "data1", "read"), asList("admin", "domain1", "data1", "write")));
    }
}
