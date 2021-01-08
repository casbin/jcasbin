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

import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.file_adapter.FilteredAdapter;
import org.casbin.jcasbin.util.Util;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.casbin.jcasbin.main.TestUtil.testHasPolicy;

public class FilteredAdapterTest {
    @Test
    public void testInitFilteredAdapter() {
        Adapter adapter = new FilteredAdapter("examples/rbac_with_domains_policy.csv");
        Enforcer enforcer = new Enforcer("examples/rbac_with_domains_model.conf");
        enforcer.setAdapter(adapter);
        testHasPolicy(enforcer, asList("admin", "domain1", "data1", "read"), false);
    }

    @Test
    public void testLoadFilteredPolicy() {
        Adapter adapter = new FilteredAdapter("examples/rbac_with_domains_policy.csv");
        Enforcer enforcer = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv", true);
        enforcer.setAdapter(adapter);

        testHasPolicy(enforcer, asList("admin", "domain1", "data1", "read"), true);
        testHasPolicy(enforcer, asList("admin", "domain2", "data2", "read"), true);

        FilteredAdapter.Filter f = new FilteredAdapter.Filter();
        f.g = new String[]{
            "", "", "domain1"
        };
        f.p = new String[]{
            "", "domain1"
        };
        enforcer.loadFilteredPolicy(f);

        testHasPolicy(enforcer, asList("admin", "domain1", "data1", "read"), true);
        testHasPolicy(enforcer, asList("admin", "domain2", "data2", "read"), false);
    }

    @Test
    public void testFilteredPolicyInvalidFilte() {
        Adapter adapter = new FilteredAdapter("examples/rbac_with_domains_policy.csv");
        Enforcer enforcer = new Enforcer("examples/rbac_with_domains_model.conf");
        enforcer.setAdapter(adapter);
        try {
            /*
            FilteredAdapter.Filter f = new FilteredAdapter.Filter();
            f.g = new String[]{
                "", "", "domain1"
            };
            f.p = new String[]{
                "", "domain1"
            };
            enforcer.loadFilteredPolicy(f);
            */
            enforcer.loadFilteredPolicy(new String[] {
                "", "domain1"
            });
        } catch (CasbinAdapterException e) {
            e.printStackTrace();
            assert true;
        }
    }

    @Test
    public void testFilteredPolicyEmptyFilter() {
        Adapter adapter = new FilteredAdapter("examples/rbac_with_domains_policy.csv");
        Enforcer enforcer = new Enforcer("examples/rbac_with_domains_model.conf");
        enforcer.setAdapter(adapter);

        enforcer.loadFilteredPolicy(null);
        Util.logPrint("Is adapter filtered:" + enforcer.isFiltered());
        assert !enforcer.isFiltered();

        enforcer.savePolicy();
    }

    @Test
    public void testUnsupportedFilteredPolicy() {
        Enforcer enforcer = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv", true);

        FilteredAdapter.Filter f = new FilteredAdapter.Filter();
        f.g = new String[]{
            "", "", "domain1"
        };
        f.p = new String[]{
            "", "domain1"
        };
        try {
            enforcer.loadFilteredPolicy(f);
        } catch (CasbinAdapterException e) {
            e.printStackTrace();
            assert true;
        }
    }

    @Test
    public void testFilteredAdapterEmptyFilepath() {
        Adapter adapter = new FilteredAdapter("");
        Enforcer enforcer = new Enforcer("examples/rbac_with_domains_model.conf");
        enforcer.setAdapter(adapter);

        enforcer.loadFilteredPolicy(null);
    }

    @Test
    public void testFilteredAdapterInvalidFilepath() {
        Adapter adapter = new FilteredAdapter("examples/does_not_exist_policy.csv");
        Enforcer enforcer = new Enforcer("examples/rbac_with_domains_model.conf");
        enforcer.setAdapter(adapter);

        try {
            enforcer.loadFilteredPolicy(null);
        } catch (CasbinAdapterException e) {
            e.printStackTrace();
            assert true;
        }
    }
}
