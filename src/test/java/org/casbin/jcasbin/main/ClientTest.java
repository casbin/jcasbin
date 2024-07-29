package org.casbin.jcasbin.main;

import org.apache.commons.cli.ParseException;
import org.casbin.jcasbin.cli.Client;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ClientTest {

    @Test
    public void testRBAC() throws ParseException {
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","alice,data1,read"}), true);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","alice,data1,write"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","alice,data2,read"}), true);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","alice,data2,write"}), true);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","bob,data1,read"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","bob,data1,write"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","bob,data2,read"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/rbac_model.conf","-p","examples/rbac_policy.csv","-e","bob,data2,write"}), true);
    }

    @Test
    public void testABAC() throws ParseException {
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","alice,domain1,data1,read"}), true);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","alice,domain1,data1,write"}), true);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","alice,domain2,data1,read"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","alice,domain2,data1,write"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","bob,domain1,data2,read"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","bob,domain1,data2,write"}), false);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","bob,domain2,data2,read"}), true);
        assertEquals(Client.clientEnforce(new String[]{"-m","examples/abac_rule_with_domains_model.conf","-p","examples/abac_rule_with_domains_policy.csv","-e","bob,domain2,data2,read"}), true);
    }

    @Test
    public void testEnforceEx() throws ParseException {
        testEnforceExCli((EnforceResult)Client.clientEnforce(new String[]{"-m", "examples/basic_model.conf", "-p", "examples/basic_policy.csv", "-ex", "alice,data1,read"}),true, new String[]{"alice", "data1", "read"});
        testEnforceExCli((EnforceResult)Client.clientEnforce(new String[]{"-m", "examples/basic_model.conf", "-p", "examples/basic_policy.csv", "-ex", "bob,data2,write"}),true, new String[]{"bob", "data2", "write"});
        testEnforceExCli((EnforceResult)Client.clientEnforce(new String[]{"-m", "examples/basic_model.conf", "-p", "examples/basic_policy.csv", "-ex", "root,data2,read"}),false, new String[]{});
        testEnforceExCli((EnforceResult)Client.clientEnforce(new String[]{"-m", "examples/basic_model.conf", "-p", "examples/basic_policy.csv", "-ex", "root,data3,read"}),false, new String[]{});
        testEnforceExCli((EnforceResult)Client.clientEnforce(new String[]{"-m", "examples/basic_model.conf", "-p", "examples/basic_policy.csv", "-ex", "jack,data3,read"}),false, new String[]{});
    }

    private void testEnforceExCli(EnforceResult enforceResult, boolean res, String[] explain) {
        assertEquals(res, enforceResult.isAllow());
        for (int i = 0; i < explain.length; i++) {
            assertEquals(explain[i], enforceResult.getExplain().get(i));
        }
    }

}
