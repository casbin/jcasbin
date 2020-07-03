package org.casbin.jcasbin.main;

import org.junit.Test;

import static org.casbin.jcasbin.main.TestUtil.testDomainEnforce;
import static org.casbin.jcasbin.main.TestUtil.testEnforce;

public class AbacAPIUnitTest {
    @Test
    public void testEval() {
        Enforcer e = new Enforcer("examples/abac_rule_model.conf", "examples/abac_rule_policy.csv");
        TestEvalRule alice = new TestEvalRule("alice", 18);
        testEnforce(e, alice, "/data1", "read", false);
        testEnforce(e, alice, "/data1", "write", false);
        alice.setAge(19);
        testEnforce(e, alice, "/data1", "read", true);
        testEnforce(e, alice, "/data1", "write", false);
        alice.setAge(25);
        testEnforce(e, alice, "/data1", "read", false);
        testEnforce(e, alice, "/data1", "write", false);
        testEnforce(e, alice, "/data2", "read", false);
        testEnforce(e, alice, "/data2", "write", true);
        alice.setAge(60);
        testEnforce(e, alice, "/data2", "read", false);
        testEnforce(e, alice, "/data2", "write", false);
    }

    @Test
    public void testEvalWithDomain() {
        Enforcer e = new Enforcer("examples/abac_rule_with_domains_model.conf", "examples/abac_rule_with_domains_policy.csv");
        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
        testDomainEnforce(e, "alice", "domain1", "data1", "write", true);
        testDomainEnforce(e, "alice", "domain2", "data1", "read", false);
        testDomainEnforce(e, "alice", "domain2", "data1", "write", false);
        testDomainEnforce(e, "bob", "domain1", "data2", "read", false);
        testDomainEnforce(e, "bob", "domain1", "data2", "write", false);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
        testDomainEnforce(e, "bob", "domain2", "data2", "read", true);
    }

    public static class TestEvalRule { //This class must be static.
        private String name;
        private int age;

        TestEvalRule(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }
    }
}
