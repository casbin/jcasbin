package org.casbin.jcasbin.main;

import org.testng.annotations.Test;
import java.io.File;
import java.io.FileWriter;
import static org.testng.Assert.*;

/**
 * Test for the 'in' operator bug with tuple literals
 * Issue: 'in' of matcher doesn't work: "m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ('data2', 'data3')"
 */
public class InOperatorBugTest {
    
    @Test
    public void testInOperatorWithTupleLiterals() throws Exception {
        // Create temporary model and policy files
        File modelFile = File.createTempFile("test_in_op_model", ".conf");
        File policyFile = File.createTempFile("test_in_op_policy", ".csv");
        modelFile.deleteOnExit();
        policyFile.deleteOnExit();
        
        // Write model with matcher containing "in" operator with tuple literals
        String modelText = "[request_definition]\n" +
                           "r = sub, obj, act\n" +
                           "\n" +
                           "[policy_definition]\n" +
                           "p = sub, obj, act\n" +
                           "\n" +
                           "[role_definition]\n" +
                           "g = _, _\n" +
                           "\n" +
                           "[policy_effect]\n" +
                           "e = some(where (p.eft == allow))\n" +
                           "\n" +
                           "[matchers]\n" +
                           "m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.obj in ('data2', 'data3')\n";
        
        try (FileWriter writer = new FileWriter(modelFile)) {
            writer.write(modelText);
        }
        
        // Write policy
        String policyText = "p, reader, data1, read\n" +
                            "p, writer, data1, write\n" +
                            "\n" +
                            "g, alice, reader\n";
        
        try (FileWriter writer = new FileWriter(policyFile)) {
            writer.write(policyText);
        }
        
        // Create enforcer
        Enforcer e = new Enforcer(modelFile.getAbsolutePath(), policyFile.getAbsolutePath());
        
        // Test 1: Should allow access because alice is a reader and wants to read data1
        assertTrue(e.enforce("alice", "data1", "read"));
        
        // Test 2: Should allow access because data2 is in the tuple ('data2', 'data3')
        assertTrue(e.enforce("alice", "data2", "read"));
        
        // Test 3: Should allow access because data3 is in the tuple ('data2', 'data3')
        assertTrue(e.enforce("alice", "data3", "write"));
        
        // Test 4: Should deny access because data4 is not in the tuple and alice is not a writer
        assertFalse(e.enforce("alice", "data4", "write"));
    }
}
