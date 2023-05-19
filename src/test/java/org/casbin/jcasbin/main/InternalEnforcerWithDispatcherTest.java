package org.casbin.jcasbin.main;

import org.casbin.jcasbin.persist.Dispatcher;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class InternalEnforcerWithDispatcherTest {

    private final static String SEC = "expected-sec";

    private final static String PTYPE = "expected-ptype";

    private final static List<String> RULE = asList("expected-new-rule-1", "expected-new-rule-2");

    private final static List<String> OLD_RULE = asList("expected-old-rule-1", "expected-old-rule-2");

    private final static int FIELD_INDEX = 0;

    private final static String[] FIELD_VALUES = new String[1];

    private InternalEnforcer enforcer;

    @Before
    public void setUp() {
        this.enforcer = new InternalEnforcer();
        this.enforcer.setDispatcher(new CustomDispatcher());
        this.enforcer.setAutoNotifyDispatcher(true);
    }

    @Test
    public void testAddPolicy() {
        boolean result = enforcer.addPolicy(SEC, PTYPE, RULE);
        assertTrue(result);
    }

    @Test
    public void testAddPolicies() {
        boolean result = enforcer.addPolicies(SEC, PTYPE, singletonList(RULE));
        assertTrue(result);
    }

    @Test
    public void testRemovePolicy() {
        boolean result = enforcer.removePolicy(SEC, PTYPE, RULE);
        assertTrue(result);
    }

    @Test
    public void testRemovePolicies() {
        boolean result = enforcer.removePolicies(SEC, PTYPE, singletonList(RULE));
        assertTrue(result);
    }

    @Test
    public void testRemoveFilteredPolicy() {
        boolean result = enforcer.removeFilteredPolicy(SEC, PTYPE, FIELD_INDEX, FIELD_VALUES);
        assertTrue(result);
    }

    @Test
    public void testUpdatePolicy() {
        boolean result = enforcer.updatePolicy(SEC, PTYPE, OLD_RULE, RULE);
        assertTrue(result);
    }

    private static class CustomDispatcher implements Dispatcher {

        @Override
        public void addPolicies(
            final String sec,
            final String ptype,
            final List<List<String>> rules
        ) {
            assertEquals(SEC, sec);
            assertEquals(PTYPE, ptype);
            assertEquals(singletonList(RULE), rules);
        }

        @Override
        public void removePolicies(
            final String sec,
            final String ptype,
            final List<List<String>> rules
        ) {
            assertEquals(SEC, sec);
            assertEquals(PTYPE, ptype);
            assertEquals(singletonList(RULE), rules);
        }

        @Override
        public void removeFilteredPolicy(
            final String sec,
            final String ptype,
            final int fieldIndex,
            final String... fieldValues
        ) {
            assertEquals(SEC, sec);
            assertEquals(PTYPE, ptype);
            assertEquals(FIELD_INDEX, fieldIndex);
            assertArrayEquals(FIELD_VALUES, fieldValues);
        }

        @Override
        public void clearPolicy() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void updatePolicy(
            final String sec,
            final String ptype,
            final List<String> oldRule,
            final List<String> newRule
        ) {
            assertEquals(SEC, sec);
            assertEquals(PTYPE, ptype);
            assertEquals(OLD_RULE, oldRule);
            assertEquals(RULE, newRule);
        }
    }
}
