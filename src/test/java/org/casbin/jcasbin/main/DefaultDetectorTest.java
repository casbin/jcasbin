// Copyright 2025 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.detector.DefaultDetector;
import org.casbin.jcasbin.detector.Detector;
import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for DefaultDetector
 */
public class DefaultDetectorTest {

    @Test
    public void testNoCycle() {
        // Create a simple hierarchy without cycles
        // u1 -> g1 -> g2
        // u2 -> g1
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("g1", "g2");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNull("Expected no cycle to be detected", result);
    }

    @Test
    public void testSimpleCycle() {
        // Create a simple cycle: A -> B -> C -> A
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        rm.addLink("C", "A");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNotNull("Expected a cycle to be detected", result);
        assertTrue("Result should contain 'Cycle detected'", result.contains("Cycle detected:"));
        assertTrue("Result should contain role A", result.contains("A"));
        assertTrue("Result should contain role B", result.contains("B"));
        assertTrue("Result should contain role C", result.contains("C"));
    }

    @Test
    public void testSelfLoop() {
        // Create a self-loop: A -> A
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("A", "A");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNotNull("Expected a cycle to be detected", result);
        assertTrue("Result should contain 'Cycle detected'", result.contains("Cycle detected:"));
        assertTrue("Result should contain role A", result.contains("A"));
    }

    @Test
    public void testTwoNodeCycle() {
        // Create a two-node cycle: A -> B -> A
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("A", "B");
        rm.addLink("B", "A");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNotNull("Expected a cycle to be detected", result);
        assertTrue("Result should contain 'Cycle detected'", result.contains("Cycle detected:"));
    }

    @Test
    public void testMultipleDisconnectedComponents() {
        // Create multiple disconnected components, no cycles
        // Component 1: u1 -> g1 -> g2
        // Component 2: u2 -> g3 -> g4
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("u1", "g1");
        rm.addLink("g1", "g2");
        rm.addLink("u2", "g3");
        rm.addLink("g3", "g4");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNull("Expected no cycle to be detected", result);
    }

    @Test
    public void testCycleInOneComponent() {
        // Create multiple components, cycle in one
        // Component 1: u1 -> g1 -> g2 (no cycle)
        // Component 2: A -> B -> C -> A (cycle)
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("u1", "g1");
        rm.addLink("g1", "g2");
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        rm.addLink("C", "A");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNotNull("Expected a cycle to be detected", result);
        assertTrue("Result should contain 'Cycle detected'", result.contains("Cycle detected:"));
    }

    @Test
    public void testComplexGraph() {
        // Create a more complex graph with a cycle
        //     g3    g2
        //    /  \  /
        //   g1   u4
        //  /  \
        // u1  u2
        // And add a cycle: u4 -> g2 -> g3 -> u4
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("g1", "g3");
        rm.addLink("u4", "g2");
        rm.addLink("u4", "g3");
        rm.addLink("g2", "g3");
        rm.addLink("g3", "u4"); // This creates a cycle
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNotNull("Expected a cycle to be detected", result);
        assertTrue("Result should contain 'Cycle detected'", result.contains("Cycle detected:"));
    }

    @Test
    public void testEmptyRoleManager() {
        // Test with an empty role manager
        RoleManager rm = new DefaultRoleManager(10);
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNull("Expected no cycle in empty graph", result);
    }

    @Test
    public void testSingleNode() {
        // Test with a single node (no edges)
        RoleManager rm = new DefaultRoleManager(10);
        // Just calling getRoles creates the node but doesn't add any edges
        rm.getRoles("A");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNull("Expected no cycle with single isolated node", result);
    }

    @Test
    public void testLargeGraph() {
        // Test performance with a large graph (10000 roles)
        // Create a chain: r0 -> r1 -> r2 -> ... -> r9999
        RoleManager rm = new DefaultRoleManager(10000);
        
        long startTime = System.currentTimeMillis();
        
        for (int i = 0; i < 9999; i++) {
            rm.addLink("r" + i, "r" + (i + 1));
        }
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        assertNull("Expected no cycle in large chain", result);
        assertTrue("Detection should complete in reasonable time (< 5 seconds)", duration < 5000);
    }

    @Test
    public void testLargeGraphWithCycle() {
        // Test with a large graph that has a cycle
        // Create a chain: r0 -> r1 -> r2 -> ... -> r9998 -> r9999 -> r0 (cycle)
        RoleManager rm = new DefaultRoleManager(10000);
        
        for (int i = 0; i < 9999; i++) {
            rm.addLink("r" + i, "r" + (i + 1));
        }
        rm.addLink("r9999", "r0"); // Create cycle
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        
        assertNotNull("Expected a cycle to be detected in large graph", result);
        assertTrue("Result should contain 'Cycle detected'", result.contains("Cycle detected:"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testUnsupportedRoleManager() {
        // Test with a RoleManager that is not DefaultRoleManager
        RoleManager rm = new RoleManager() {
            @Override
            public void clear() {}
            
            @Override
            public void addLink(String name1, String name2, String... domain) {}
            
            @Override
            public void deleteLink(String name1, String name2, String... domain) {}
            
            @Override
            public boolean hasLink(String name1, String name2, String... domain) {
                return false;
            }
            
            @Override
            public java.util.List<String> getRoles(String name, String... domain) {
                return null;
            }
            
            @Override
            public java.util.List<String> getUsers(String name, String... domain) {
                return null;
            }
            
            @Override
            public void printRoles() {}
        };
        
        Detector detector = new DefaultDetector();
        detector.check(rm); // Should throw IllegalArgumentException
    }

    @Test
    public void testCycleAfterClear() {
        // Test that clearing a role manager removes the cycle
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        rm.addLink("C", "A");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        assertNotNull("Expected a cycle before clear", result);
        
        rm.clear();
        result = detector.check(rm);
        assertNull("Expected no cycle after clear", result);
    }

    @Test
    public void testCycleDetectionAfterDelete() {
        // Test that deleting a link breaks the cycle
        RoleManager rm = new DefaultRoleManager(10);
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        rm.addLink("C", "A");
        
        Detector detector = new DefaultDetector();
        String result = detector.check(rm);
        assertNotNull("Expected a cycle before delete", result);
        
        rm.deleteLink("C", "A");
        result = detector.check(rm);
        assertNull("Expected no cycle after breaking the cycle", result);
    }
}
