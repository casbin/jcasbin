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
import org.casbin.jcasbin.util.Util;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Set;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.CoreEnforcer.newModel;
import static org.casbin.jcasbin.main.TestUtil.testEnforce;
import static org.casbin.jcasbin.main.TestUtil.testGetPolicy;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class EnforcerUnitTest {
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
    public void testRBACModelInMemory2() {
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
    public void testNotUsedRBACModelInMemory() {
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

    @Test
    public void testReloadPolicy() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.loadPolicy();
        testGetPolicy(e, asList(asList("alice", "data1", "read"), asList("bob", "data2", "write"), asList("data2_admin", "data2", "read"), asList("data2_admin", "data2", "write")));
    }

    @Test
    public void testSavePolicy() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.savePolicy();
    }

    @Test
    public void testClearPolicy() {
        Enforcer e = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        e.clearPolicy();
    }

    @Test
    public void testEnableEnforce() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        e.enableEnforce(false);
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", true);
        testEnforce(e, "alice", "data2", "read", true);
        testEnforce(e, "alice", "data2", "write", true);
        testEnforce(e, "bob", "data1", "read", true);
        testEnforce(e, "bob", "data1", "write", true);
        testEnforce(e, "bob", "data2", "read", true);
        testEnforce(e, "bob", "data2", "write", true);

        e.enableEnforce(true);
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
    public void testEnableLog() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv", true);
        // The log is enabled by default, so the above is the same with:
        // Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);

        // The log can also be enabled or disabled at run-time.
        e.enableLog(false);
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
    public void testEnableAutoSave() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");

        e.enableAutoSave(false);
        // Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
        // it doesn't affect the policy in the storage.
        e.removePolicy("alice", "data1", "read");
        // Reload the policy from the storage to see the effect.
        e.loadPolicy();
        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);

        e.enableAutoSave(true);
        // Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
        // but also affects the policy in the storage.
        e.removePolicy("alice", "data1", "read");

        // However, the file adapter doesn't implement the AutoSave feature, so enabling it has no effect at all here.

        // Reload the policy from the storage to see the effect.
        e.loadPolicy();
        testEnforce(e, "alice", "data1", "read", true); // Will not be false here.
        testEnforce(e, "alice", "data1", "write", false);
        testEnforce(e, "alice", "data2", "read", false);
        testEnforce(e, "alice", "data2", "write", false);
        testEnforce(e, "bob", "data1", "read", false);
        testEnforce(e, "bob", "data1", "write", false);
        testEnforce(e, "bob", "data2", "read", false);
        testEnforce(e, "bob", "data2", "write", true);
    }

    @Test
    public void testInitWithAdapter() {
        Adapter adapter = new FileAdapter("examples/basic_policy.csv");
        Enforcer e = new Enforcer("examples/basic_model.conf", adapter);

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
    public void testRoleLinks() {
        Enforcer e = new Enforcer("examples/rbac_model.conf");
        e.enableAutoBuildRoleLinks(false);
        e.buildRoleLinks();
        e.enforce("user501", "data9", "read");
    }

    @Test
    public void testGetAndSetModel() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        Enforcer e2 = new Enforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv");

        testEnforce(e, "root", "data1", "read", false);

        e.setModel(e2.getModel());

        testEnforce(e, "root", "data1", "read", true);
    }

    @Test
    public void testGetAndSetAdapterInMem() {
        Enforcer e = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        Enforcer e2 = new Enforcer("examples/basic_model.conf", "examples/basic_inverse_policy.csv");

        testEnforce(e, "alice", "data1", "read", true);
        testEnforce(e, "alice", "data1", "write", false);

        Adapter a2 = e2.getAdapter();
        e.setAdapter(a2);
        e.loadPolicy();

        testEnforce(e, "alice", "data1", "read", false);
        testEnforce(e, "alice", "data1", "write", true);
    }

    @Test
    public void testSetAdapterFromFile() {
        Enforcer e = new Enforcer("examples/basic_model.conf");

        testEnforce(e, "alice", "data1", "read", false);

        Adapter a = new FileAdapter("examples/basic_policy.csv");
        e.setAdapter(a);
        e.loadPolicy();

        testEnforce(e, "alice", "data1", "read", true);
    }

    @Test
    public void testInitEmpty() {
        Enforcer e = new Enforcer();

        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        Adapter a = new FileAdapter("examples/keymatch_policy.csv");

        e.setModel(m);
        e.setAdapter(a);
        e.loadPolicy();

        testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
    }

    @Test
    public void testKeyMatch4Func() {
        Enforcer e = new Enforcer("examples/keymatch4_model.conf", "examples/keymatch4_policy.csv");

        testEnforce(e, "alice", "/alice_data/resource/1/child/1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource/1/child/2", "GET", false);

        testEnforce(e, "alice", "/alice_data2/1/using/2", "GET", true);
        testEnforce(e, "alice", "/alice_data2/1/using/1", "GET", true);
        testEnforce(e, "alice", "/alice_data3/1/using/2", "GET", false);

        testEnforce(e, "alice", "/alice_data/resource/1/child/1/child2/1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource/1/child2/1/child/1/child2/1", "GET", false);

        testEnforce(e, "alice", "/alice_data/resource/1/child1", "GET", true);
        testEnforce(e, "alice", "/alice_data/resource/1/child2", "GET", false);
    }

    @Test
    public void testInitEmptyByInputStream() {
        Enforcer e = new Enforcer();

        Model m = newModel();
        m.addDef("r", "r", "sub, obj, act");
        m.addDef("p", "p", "sub, obj, act");
        m.addDef("e", "e", "some(where (p.eft == allow))");
        m.addDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)");

        try (FileInputStream fis = new FileInputStream("examples/keymatch_policy.csv")) {
            Adapter a = new FileAdapter(fis);

            e.setModel(m);
            e.setAdapter(a);
            e.loadPolicy();

            testEnforce(e, "alice", "/alice_data/resource1", "GET", true);
        } catch (IOException ex) {
            ex.printStackTrace();
        }

    }

    @Test
    public void testEnforceParamCheck(){
        Enforcer e = new Enforcer("examples/rbac_model.conf");
        assertTrue(e.validateEnforce("user501", "data9", "read", "too many params")); //warn only
        assertFalse(e.validateEnforce("data9", "read"));//throw error
    }

    @Test
    public void testGetPermittedActions() {
        Enforcer e = new Enforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv", true);
        String sub = "alice";
        String obj = "data1";
        Set<String> actions = e.getPermittedActions(sub, obj);
        Util.logPrint(sub + " has permissions to access " + obj + " with following actions:");
        for (String action :actions) {
            Util.logPrint(action); //alice should have read-only access to data1
        }

        obj = "data2";

        actions = e.getPermittedActions(sub, obj);
        Util.logPrint(sub + " has permissions to access " + obj + " with following actions:");
        for (String action :actions) {
            Util.logPrint(action); //alice should have read and write access to data2
        }

        e = new Enforcer("examples/abac_model.conf", "", true);
        ModelUnitTest.TestResource data1 = new ModelUnitTest.TestResource("data1", "alice");
        actions = e.getPermittedActions(sub, data1);

        Util.logPrint(sub + " has permissions to access " + data1.name + " with following actions:");
        for (String action :actions) {
            // The result shows that alice should have no access to data1,
            // because no action defines.
            // This method has no meaning for ABAC model,
            // because under this model,
            // the owner of a resource has any permission to the resource it owns.
            Util.logPrint(action);
        }
    }
}
