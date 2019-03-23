package org.casbin.jcasbin.main;

import org.casbin.jcasbin.persist.io.InputStreamAdapter;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

public class TestInputStreamAdapter {

    private static InputStreamAdapter inputStreamAdapter;

    @BeforeClass
    public static void init() throws IOException {
        InputStream policyStream = EnforcerClasspathConfigLoadingTest.class.getClassLoader().getResourceAsStream("authz_policy.csv");
        inputStreamAdapter = new InputStreamAdapter(policyStream);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testIsAdapterSavePolicy() {
        inputStreamAdapter.savePolicy(null);
        Assert.fail("UnsupportedOperationException expected.");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testIsAdapterAddPolicy() {
        inputStreamAdapter.addPolicy(null, null, null);
        Assert.fail("UnsupportedOperationException expected.");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testIsAdapterRemovePolicy() {
        inputStreamAdapter.removePolicy(null, null, null);
        Assert.fail("UnsupportedOperationException expected.");
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testIsAdapterRemoveFilteredPolicy() {
        inputStreamAdapter.removeFilteredPolicy(null, null, 0, null);
        Assert.fail("UnsupportedOperationException expected.");
    }

}
