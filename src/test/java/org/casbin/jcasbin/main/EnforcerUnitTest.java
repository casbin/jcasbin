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

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.junit.Test;

import static org.casbin.jcasbin.main.CoreEnforcer.newModel;
import static org.junit.Assert.assertEquals;

public class EnforcerUnitTest {
    public void testEnforce(Enforcer e, String sub, String obj, String act, boolean res) {
        assertEquals(e.enforce(sub, obj, act), res);
    }

    @Test
    public void testKeyMatchModelInMemory() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        Adapter a = new FileAdapter("examples/keymatch_policy.csv");

        Enforcer e = new Enforcer(m, a);

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

        e = new Enforcer(m);
        a.loadPolicy(e.getModel());

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
    public void testKeyMatchModelInMemoryDeny() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "!some(where (p.eft == deny))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        Adapter a = new FileAdapter("examples/keymatch_policy.csv");

        Enforcer e = new Enforcer(m, a);

        testEnforce(e, "alice", "/alice_data/resource2", "POST", true);
    }

    @Test
    public void testRBACModelInMemoryIndeterminate() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("g", "g", "_, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");

        Enforcer e = new Enforcer(m);

        e.addPermissionForUser("alice", "data1", "invalid");

        testEnforce(e, "alice", "data1", "read", false);
    }

    @Test
    public void testRBACModelInMemory() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("g", "g", "_, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");

        Enforcer e = new Enforcer(m);

        e.addPermissionForUser("alice", "data1", "read");
        e.addPermissionForUser("bob", "data2", "write");
        e.addPermissionForUser("data2_admin", "data2", "read");
        e.addPermissionForUser("data2_admin", "data2", "write");
        e.addRoleForUser("alice", "data2_admin");

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
    public void TestRBACModelInMemory2() {
        String text =
		    "[request_definition]\n"
            + "r = sub, obj, act\n"
            + "\n"
            + "[policy_definition]\n"
            + "p = sub, obj, act\n"
            + "\n"
            + "[role_definition]\n"
            + "g = _, _\n"
            + "\n"
            + "[policy_effect]\n"
            + "e = some(where (p.eft == allow))\n"
            + "\n"
            + "[matchers]\n"
            + "m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act\n";

        Model m = newModel(text);
        // The above is the same as:
        // Model m = newModel();
        // m.loadModelFromText(text);

        Enforcer e = new Enforcer(m);

        e.addPermissionForUser("alice", "data1", "read");
        e.addPermissionForUser("bob", "data2", "write");
        e.addPermissionForUser("data2_admin", "data2", "read");
        e.addPermissionForUser("data2_admin", "data2", "write");
        e.addRoleForUser("alice", "data2_admin");

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
    public void TestNotUsedRBACModelInMemory() {
        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("g", "g", "_, _");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");

        Enforcer e = new Enforcer(m);

        e.addPermissionForUser("alice", "data1", "read");
        e.addPermissionForUser("bob", "data2", "write");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }
}
