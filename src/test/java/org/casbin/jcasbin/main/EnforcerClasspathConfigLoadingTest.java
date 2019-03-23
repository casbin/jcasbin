package org.casbin.jcasbin.main;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class EnforcerClasspathConfigLoadingTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { "alice", "/services/data/list", "GET", true },
                { "bob", "/services/data/list", "GET", true },
                { "bob", "/services/data/id/xxx", "PUT", true },
                { "alice", "/services/data/id/xxx", "PUT", false },
                { "bob", "/services/data/id/xxx", "DELETE", true },
                { "alice", "/services/data/id/xxx", "DELETE", false },
        });
    }

    private static Enforcer enforcer;

    @BeforeClass
    public static void init() throws IOException {
        InputStream  modelStream = EnforcerClasspathConfigLoadingTest.class.getClassLoader().getResourceAsStream("authz_model.conf");
        InputStream policyStream = EnforcerClasspathConfigLoadingTest.class.getClassLoader().getResourceAsStream("authz_policy.csv");
        enforcer = new Enforcer(modelStream, policyStream);
        modelStream.close();
        policyStream.close();
    }

    private final String user;
    private final String path;
    private final String method;
    private final boolean expectedResult;

    public EnforcerClasspathConfigLoadingTest(String user, String path, String method, boolean expectedResult) {
        this.user = user;
        this.path = path;
        this.method = method;
        this.expectedResult = expectedResult;
    }

    @Test
    public void testLoadConfigFromClasspath() {
        boolean result = enforcer.enforce(user, path, method);
        Assert.assertTrue(result == expectedResult);
    }

}
