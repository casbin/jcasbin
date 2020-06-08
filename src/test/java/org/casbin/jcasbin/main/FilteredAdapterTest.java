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
