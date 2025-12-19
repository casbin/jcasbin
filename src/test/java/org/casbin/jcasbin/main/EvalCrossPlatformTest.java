// Copyright 2024 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.util.ExpressionEvaluator;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Integration test to demonstrate the fix for the eval() function issue.
 * This test validates that the expression evaluator prevents the use of
 * aviatorscript-specific syntax mentioned in the issue, ensuring
 * cross-platform compatibility.
 */
public class EvalCrossPlatformTest {

    /**
     * Test that aviatorscript-specific syntax mentioned in the issue is blocked.
     * Issue mentioned: seq.list(), string.startsWith(), string.endsWith(), include(seq.list(),xx)
     */
    @Test
    public void testAviatorScriptSyntaxFromIssue_IsBlocked() {
        // All these expressions from the issue description should be blocked
        
        // 1. seq.list() syntax
        try {
            ExpressionEvaluator.validateExpression("seq.list('A', 'B')");
            fail("seq.list() should be blocked");
        } catch (IllegalArgumentException e) {
            assertTrue("Should mention non-standard operations", 
                e.getMessage().contains("non-standard Casbin operations"));
        }
        
        // 2. string.startsWith() syntax
        try {
            ExpressionEvaluator.validateExpression("string.startsWith(r.obj, '/data')");
            fail("string.startsWith() should be blocked");
        } catch (IllegalArgumentException e) {
            assertTrue("Should mention non-standard operations", 
                e.getMessage().contains("non-standard Casbin operations"));
        }
        
        // 3. string.endsWith() syntax
        try {
            ExpressionEvaluator.validateExpression("string.endsWith(r.obj, '.txt')");
            fail("string.endsWith() should be blocked");
        } catch (IllegalArgumentException e) {
            assertTrue("Should mention non-standard operations", 
                e.getMessage().contains("non-standard Casbin operations"));
        }
        
        // 4. include(seq.list(),xx) syntax
        try {
            ExpressionEvaluator.validateExpression("include(seq.list('admin', 'user'), r.sub.role)");
            fail("include(seq.list(),xx) should be blocked");
        } catch (IllegalArgumentException e) {
            assertTrue("Should mention non-standard operations", 
                e.getMessage().contains("non-standard Casbin operations"));
        }
    }

    /**
     * Test that standard Casbin expressions work correctly.
     * These should be portable across all Casbin implementations.
     */
    @Test
    public void testStandardCasbinExpressions_AreAllowed() {
        // All these standard expressions should work
        String[] standardExpressions = {
            // Property access
            "r.sub.name == 'alice'",
            "r.sub.age > 18",
            "r.obj == '/data1'",
            "r.act == 'read'",
            
            // Logical operators
            "r.sub.age > 18 && r.sub.age < 60",
            "r.sub.name == 'alice' || r.sub.name == 'bob'",
            "!(r.sub.blocked == true)",
            
            // Comparison operators
            "r.sub.level >= 5",
            "r.sub.score != 0",
            "r.domain == 'domain1'",
            
            // Arithmetic operations
            "r.sub.age + 10 > 28",
            "r.sub.count * 2 <= 100",
            
            // Registered functions (these are part of standard Casbin)
            "keyMatch(r.obj, '/api/*')",
            "regexMatch(r.obj, '^/data[0-9]+$')",
            "custom(r.obj)"
        };
        
        for (String expr : standardExpressions) {
            try {
                ExpressionEvaluator.validateExpression(expr);
                // Success - standard expression is allowed
            } catch (IllegalArgumentException e) {
                fail("Standard expression should be allowed: " + expr + " - Error: " + e.getMessage());
            }
        }
    }

    /**
     * Test that the solution achieves cross-platform compatibility.
     * The same expressions should work identically on Go, Node.js, Python, etc.
     */
    @Test
    public void testCrossPlatformCompatibility() {
        // These expressions use only standard operators that are available
        // in all Casbin implementations
        
        String[] crossPlatformExpressions = {
            // Instead of seq.list('A', 'B'), use standard comparisons:
            "r.sub.role == 'admin' || r.sub.role == 'moderator'",
            
            // Instead of string.startsWith(), use keyMatch or regexMatch:
            "keyMatch(r.obj, '/api/*')",
            "regexMatch(r.obj, '^/api/')",
            
            // Instead of string.endsWith(), use regexMatch:
            "regexMatch(r.obj, '\\\\.txt$')",
            
            // Instead of include(seq.list(),xx), use logical OR:
            "r.sub.dept == 'engineering' || r.sub.dept == 'sales'"
        };
        
        for (String expr : crossPlatformExpressions) {
            try {
                ExpressionEvaluator.validateExpression(expr);
                // Success - cross-platform compatible expression
            } catch (IllegalArgumentException e) {
                fail("Cross-platform expression should be allowed: " + expr);
            }
        }
    }

    /**
     * Test that security is improved by blocking operations beyond Casbin spec.
     */
    @Test
    public void testSecurityImprovement_BlocksUnsafeOperations() {
        // These operations go beyond Casbin specification and could be security risks
        String[] unsafeOperations = {
            "new java.io.File('/etc/passwd')",
            "import java.lang.System",
            "let x = System.getProperty('user.home')",
            "fn hack() { return 'exploit' }",
            "lambda(x) -> System.exit(0)",
            "for (i = 0; i < 1000000; i++)",  // potential DoS
            "while (true)",                    // infinite loop
            "math.random()"                    // non-deterministic
        };
        
        for (String expr : unsafeOperations) {
            try {
                ExpressionEvaluator.validateExpression(expr);
                fail("Unsafe operation should be blocked: " + expr);
            } catch (IllegalArgumentException e) {
                // Success - unsafe operation is blocked
                assertTrue("Should indicate non-standard operations", 
                    e.getMessage().contains("non-standard Casbin operations"));
            }
        }
    }
}
