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

import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.Util;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class TestUtil {
    static void testEnforce(Enforcer e, Object sub, Object obj, String act, boolean res) {
        assertEquals(res, e.enforce(sub, obj, act));
    }

    static void testEnforceWithoutUsers(Enforcer e, String obj, String act, boolean res) {
        assertEquals(res, e.enforce(obj, act));
    }

    static void testDomainEnforce(Enforcer e, String sub, String dom, String obj, String act, boolean res) {
        assertEquals(res, e.enforce(sub, dom, obj, act));
    }

    static void testGetPolicy(Enforcer e, List<List<String>> res) {
        List<List<String>> myRes = e.getPolicy();
        Util.logPrint("Policy: " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Policy: " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetFilteredPolicy(Enforcer e, int fieldIndex, List<List<String>> res, String... fieldValues) {
        List<List<String>> myRes = e.getFilteredPolicy(fieldIndex, fieldValues);
        Util.logPrint("Policy for " + Util.paramsToString(fieldValues) + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Policy for " + Util.paramsToString(fieldValues) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetGroupingPolicy(Enforcer e, List<List<String>> res) {
        List<List<String>> myRes = e.getGroupingPolicy();
        Util.logPrint("Grouping policy: " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Grouping policy: " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetFilteredGroupingPolicy(Enforcer e, int fieldIndex, List<List<String>> res, String... fieldValues) {
        List<List<String>> myRes = e.getFilteredGroupingPolicy(fieldIndex, fieldValues);
        Util.logPrint("Grouping policy for " + Util.paramsToString(fieldValues) + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Grouping policy for " + Util.paramsToString(fieldValues) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasPolicy(Enforcer e, List<String> policy, boolean res) {
        boolean myRes = e.hasPolicy(policy);
        Util.logPrint("Has policy " + Util.arrayToString(policy) + ": " + myRes);

        if (res != myRes) {
            fail("Has policy " + Util.arrayToString(policy) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasGroupingPolicy(Enforcer e, List<String> policy, boolean res) {
        boolean myRes = e.hasGroupingPolicy(policy);
        Util.logPrint("Has grouping policy " + Util.arrayToString(policy) + ": " + myRes);

        if (res != myRes) {
            fail("Has grouping policy " + Util.arrayToString(policy) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetRoles(Enforcer e, String name, List<String> res) {
        List<String> myRes = e.getRolesForUser(name);
        Util.logPrint("Roles for " + name + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Roles for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetUsers(Enforcer e, String name, List<String> res) {
        List<String> myRes = e.getUsersForRole(name);
        Util.logPrint("Users for " + name + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Users for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasRole(Enforcer e, String name, String role, boolean res) {
        boolean myRes = e.hasRoleForUser(name, role);
        Util.logPrint(name + " has role " + role + ": " + myRes);

        if (res != myRes) {
            fail(name + " has role " + role + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetPermissions(Enforcer e, String name, List<List<String>> res) {
        List<List<String>> myRes = e.getPermissionsForUser(name);
        Util.logPrint("Permissions for " + name + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Permissions for " + name + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testHasPermission(Enforcer e, String name, List<String> permission, boolean res) {
        boolean myRes = e.hasPermissionForUser(name, permission);
        Util.logPrint(name + " has permission " + Util.arrayToString(permission) + ": " + myRes);

        if (res != myRes) {
            fail(name + " has permission " + Util.arrayToString(permission) + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetRolesInDomain(Enforcer e, String name, String domain, List<String> res) {
        List<String> myRes = e.getRolesForUserInDomain(name, domain);
        Util.logPrint("Roles for " + name + " under " + domain + ": " + myRes);

        if (!Util.setEquals(res, myRes)) {
            fail("Roles for " + name + " under " + domain + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetPermissionsInDomain(Enforcer e, String name, String domain, List<List<String>> res) {
        List<List<String>> myRes = e.getPermissionsForUserInDomain(name, domain);
        Util.logPrint("Permissions for " + name + " under " + domain + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Permissions for " + name + " under " + domain + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGetImplicitPermissionsInDomain(Enforcer e, String name, String domain, List<List<String>> res) {
        List<List<String>> myRes = e.getImplicitPermissionsForUserInDomain(name, domain);
        Util.logPrint("Permissions for " + name + " under " + domain + ": " + myRes);

        if (!Util.array2DEquals(res, myRes)) {
            fail("Permissions for " + name + " under " + domain + ": " + myRes + ", supposed to be " + res);
        }
    }

    static void testGlobMatch(String key1, String key2, boolean res) {
        assertEquals(res, BuiltInFunctions.globMatch(key1, key2));
    }
}
