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
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for Detector integration with DefaultRoleManager.
 * Tests cycle detection without depending on Enforcer.
 */
public class DetectorTest {

    @Test
    public void testValidInheritanceChainNoException() {
        // Construct a DefaultRoleManager with detector
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // Add valid inheritance chains: u1 -> g1 -> g2 -> g3
        rm.addLink("u1", "g1");
        rm.addLink("g1", "g2");
        rm.addLink("g2", "g3");
        
        // Verify no exception was thrown and the links exist
        assertTrue("u1 should have link to g1", rm.hasLink("u1", "g1"));
        assertTrue("u1 should have link to g2", rm.hasLink("u1", "g2"));
        assertTrue("u1 should have link to g3", rm.hasLink("u1", "g3"));
        
        // checkCycles should not throw exception for valid hierarchy
        rm.checkCycles();
    }

    @Test
    public void testMultipleBranchesNoException() {
        // Create a more complex valid hierarchy
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // Create tree structure:
        //       g3
        //      /  \
        //    g1    g2
        //   /  \    |
        //  u1  u2  u3
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("u3", "g2");
        rm.addLink("g1", "g3");
        rm.addLink("g2", "g3");
        
        // Verify all links work correctly
        assertTrue("u1 should have link to g3", rm.hasLink("u1", "g3"));
        assertTrue("u2 should have link to g3", rm.hasLink("u2", "g3"));
        assertTrue("u3 should have link to g3", rm.hasLink("u3", "g3"));
        
        // checkCycles should not throw exception for valid hierarchy
        rm.checkCycles();
    }

    @Test
    public void testCycleDetectionThreeNodes() {
        // Test cycle A -> B -> C -> A
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // Add all links including the one that creates a cycle
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        rm.addLink("C", "A");  // Creates a cycle, but addLink doesn't throw
        
        // Verify the link was added
        assertTrue("C should have link to A", rm.hasLink("C", "A"));
        
        // checkCycles should throw exception when called
        try {
            rm.checkCycles();
            fail("Expected IllegalArgumentException due to cycle detection");
        } catch (IllegalArgumentException e) {
            // Expected exception
            assertTrue("Exception message should contain 'Cycle detected'", 
                      e.getMessage().contains("Cycle detected"));
        }
    }

    @Test
    public void testSelfLoopDetection() {
        // Test self-loop: A -> A
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // addLink doesn't throw, just adds the link
        rm.addLink("A", "A");
        
        // checkCycles should throw exception
        try {
            rm.checkCycles();
            fail("Expected IllegalArgumentException due to self-loop");
        } catch (IllegalArgumentException e) {
            // Expected exception
            assertTrue("Exception message should contain 'Cycle detected'", 
                      e.getMessage().contains("Cycle detected"));
        }
    }

    @Test
    public void testTwoNodeCycleDetection() {
        // Test two-node cycle: A -> B -> A
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        rm.addLink("A", "B");
        rm.addLink("B", "A");  // Creates a cycle, but addLink doesn't throw
        
        // Verify both links were added
        assertTrue("A should have link to B", rm.hasLink("A", "B"));
        assertTrue("B should have link to A", rm.hasLink("B", "A"));
        
        // checkCycles should throw exception
        try {
            rm.checkCycles();
            fail("Expected IllegalArgumentException due to cycle");
        } catch (IllegalArgumentException e) {
            // Expected exception
            assertTrue("Exception message should contain 'Cycle detected'", 
                      e.getMessage().contains("Cycle detected"));
        }
    }

    @Test
    public void testComplexGraphCycleDetection() {
        // Test complex graph with cycle
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // Build a complex structure with a cycle
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("g1", "g2");
        rm.addLink("g2", "g3");
        rm.addLink("u3", "g3");
        rm.addLink("g3", "g1");  // Creates a cycle
        
        // Verify the link was added
        assertTrue("g3 should have link to g1", rm.hasLink("g3", "g1"));
        
        // checkCycles should throw exception
        try {
            rm.checkCycles();
            fail("Expected IllegalArgumentException due to cycle");
        } catch (IllegalArgumentException e) {
            // Expected exception
            assertTrue("Exception message should contain 'Cycle detected'", 
                      e.getMessage().contains("Cycle detected"));
        }
        
        // Verify existing structure is intact
        assertTrue("u1 should still reach g3", rm.hasLink("u1", "g3"));
        assertTrue("u2 should still reach g3", rm.hasLink("u2", "g3"));
    }

    @Test
    public void testDetectorCanBeSetToNull() {
        // Test that detector can be set to null (disabled)
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        rm.addLink("A", "B");
        
        // Disable detector
        rm.setDetector(null);
        
        // Now cycles can be created and checkCycles won't throw
        rm.addLink("B", "A");
        
        // Both links should exist
        assertTrue("A should have link to B", rm.hasLink("A", "B"));
        assertTrue("B should have link to A", rm.hasLink("B", "A"));
        
        // checkCycles should not throw when detector is null
        rm.checkCycles();  // Should not throw
    }

    @Test
    public void testNoDetectorNoCycleCheck() {
        // Test that without detector, cycles are not detected
        DefaultRoleManager rm = new DefaultRoleManager(10);
        // Don't set detector
        
        // Create a cycle: A -> B -> A
        rm.addLink("A", "B");
        rm.addLink("B", "A");
        
        // Should not throw exception
        assertTrue("A should have link to B", rm.hasLink("A", "B"));
        assertTrue("B should have link to A", rm.hasLink("B", "A"));
        
        // checkCycles should not throw when detector is not set
        rm.checkCycles();  // Should not throw
    }

    @Test
    public void testMultipleDisconnectedComponents() {
        // Test with multiple disconnected valid components
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // Component 1: u1 -> g1 -> g2
        rm.addLink("u1", "g1");
        rm.addLink("g1", "g2");
        
        // Component 2: u2 -> g3 -> g4
        rm.addLink("u2", "g3");
        rm.addLink("g3", "g4");
        
        // Verify all links work
        assertTrue("u1 should reach g2", rm.hasLink("u1", "g2"));
        assertTrue("u2 should reach g4", rm.hasLink("u2", "g4"));
        
        // Components should be independent
        assertFalse("u1 should not reach g4", rm.hasLink("u1", "g4"));
        assertFalse("u2 should not reach g2", rm.hasLink("u2", "g2"));
        
        // checkCycles should not throw for valid disconnected components
        rm.checkCycles();
    }

    @Test
    public void testLongChainNoCycle() {
        // Test a long chain without cycles
        DefaultRoleManager rm = new DefaultRoleManager(100);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        final int CHAIN_LENGTH = 10;
        
        // Create chain: r0 -> r1 -> r2 -> ... -> r9
        for (int i = 0; i < CHAIN_LENGTH - 1; i++) {
            rm.addLink("r" + i, "r" + (i + 1));
        }
        
        // Verify chain works
        assertTrue("r0 should reach r9", rm.hasLink("r0", "r" + (CHAIN_LENGTH - 1)));
        assertTrue("r5 should reach r9", rm.hasLink("r5", "r" + (CHAIN_LENGTH - 1)));
        
        // checkCycles should not throw for valid chain
        rm.checkCycles();
        
        // Add a link that creates a cycle
        rm.addLink("r" + (CHAIN_LENGTH - 1), "r0");
        
        // checkCycles should throw after adding cycle
        try {
            rm.checkCycles();
            fail("Expected IllegalArgumentException due to cycle");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should contain 'Cycle detected'", 
                      e.getMessage().contains("Cycle detected"));
        }
    }

    @Test
    public void testDiamondStructure() {
        // Test diamond structure (common pattern in role hierarchies)
        //       admin
        //       /   \
        //   editor  viewer
        //       \   /
        //       user
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        rm.addLink("user", "editor");
        rm.addLink("user", "viewer");
        rm.addLink("editor", "admin");
        rm.addLink("viewer", "admin");
        
        // Verify the structure
        assertTrue("user should reach admin through editor", rm.hasLink("user", "admin"));
        
        // checkCycles should not throw for valid diamond structure
        rm.checkCycles();
        
        // Add a link that creates a cycle
        rm.addLink("admin", "user");
        
        // checkCycles should throw after adding cycle
        try {
            rm.checkCycles();
            fail("Expected IllegalArgumentException due to cycle");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should contain 'Cycle detected'", 
                      e.getMessage().contains("Cycle detected"));
        }
    }

    @Test
    public void testIdempotencyWithExistingLink() {
        // Test that adding an existing link multiple times is idempotent
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // Add initial valid links
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        
        // Verify initial state
        assertTrue("A should have link to B", rm.hasLink("A", "B"));
        assertTrue("A should have link to C", rm.hasLink("A", "C"));
        
        // Add the same link again (should be idempotent)
        rm.addLink("A", "B");
        
        // Verify the link still exists
        assertTrue("A should still have link to B after re-adding", rm.hasLink("A", "B"));
        assertTrue("A should still have link to C after re-adding", rm.hasLink("A", "C"));
        
        // checkCycles should not throw for valid chain
        rm.checkCycles();
        
        // Add another link
        rm.addLink("C", "D");
        assertTrue("C should have link to D", rm.hasLink("C", "D"));
        
        // Re-add an existing link (A->B) should still be idempotent
        rm.addLink("A", "B");
        
        // Verify all links still exist
        assertTrue("A should still have link to B", rm.hasLink("A", "B"));
        assertTrue("B should still have link to C", rm.hasLink("B", "C"));
        assertTrue("C should still have link to D", rm.hasLink("C", "D"));
        
        // checkCycles should still not throw
        rm.checkCycles();
    }

    @Test
    public void testIdempotencyDoesNotPreventCycleDetection() {
        // Test that the idempotency check doesn't interfere with cycle detection
        DefaultRoleManager rm = new DefaultRoleManager(10);
        Detector detector = new DefaultDetector();
        rm.setDetector(detector);
        
        // Create a valid chain
        rm.addLink("A", "B");
        rm.addLink("B", "C");
        
        // Add a link that creates a cycle
        rm.addLink("C", "A");
        
        // Verify the link was added
        assertTrue("C should have link to A", rm.hasLink("C", "A"));
        
        // checkCycles should throw exception
        try {
            rm.checkCycles();
            fail("Expected IllegalArgumentException due to cycle");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should contain 'Cycle detected'", 
                      e.getMessage().contains("Cycle detected"));
        }
    }
}
