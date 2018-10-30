package org.casbin.jcasbin.main;

import org.casbin.jcasbin.rbac.GroupRoleManager;
import org.junit.Test;

import static org.casbin.jcasbin.main.TestUtil.testDomainEnforce;

public class GroupRoleManagerTest {
    @Test
    public void testGroupRoleManager() {
        Enforcer e = new Enforcer("examples/group_with_domain_model.conf", "examples/group_with_domain_policy.csv");
        e.setRoleManager(new GroupRoleManager(10));
        e.buildRoleLinks();

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
    }

}
