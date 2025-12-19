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

import com.googlecode.aviator.AviatorEvaluator;
import com.googlecode.aviator.AviatorEvaluatorInstance;
import org.casbin.jcasbin.util.ExpressionEvaluator;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class ExpressionEvaluatorTest {

    @Test
    public void testValidateExpression_StandardOperations_ShouldPass() {
        // Test standard Casbin operations that should be allowed
        String[] validExpressions = {
            "r.sub.age > 18",
            "r.sub.name == 'alice'",
            "r.sub.age >= 18 && r.obj == '/data1'",
            "r.domain == 'domain1'",
            "r.sub.age < 60",
            "r.sub.age > 18 && r.sub.age < 60",
            "r.sub.name == 'alice' || r.sub.name == 'bob'",
            "!(r.sub.age > 18)",
            "r.sub.age + 10 > 28",
            "r.sub.age * 2 < 100",
            "r.sub.score >= 90 && r.sub.grade == 'A'",
            "custom(r.obj) && r.act == 'read'"
        };

        for (String expr : validExpressions) {
            try {
                ExpressionEvaluator.validateExpression(expr);
            } catch (IllegalArgumentException e) {
                fail("Valid expression should not throw exception: " + expr + " - " + e.getMessage());
            }
        }
    }

    @Test
    public void testValidateExpression_AviatorScriptFeatures_ShouldFail() {
        // Test aviatorscript-specific features that should be blocked
        String[] invalidExpressions = {
            "seq.list('A', 'B')",
            "string.startsWith(r.obj, '/data')",
            "string.endsWith(r.obj, '.txt')",
            "include(seq.list('A', 'B'), r.sub)",
            "math.abs(r.sub.age)",
            "let x = 10",
            "fn add(a, b) { return a + b }",
            "lambda(x) -> x + 1",
            "for (i = 0; i < 10; i++)",
            "while (true)",
            "new java.util.ArrayList()",
            "import java.util.List",
            // Test case-insensitive variants to prevent bypass
            "Seq.list('A', 'B')",
            "SEQ.LIST('A', 'B')",
            "String.StartsWith(r.obj, '/data')",
            "STRING.ENDSWITH(r.obj, '.txt')",
            "Math.Abs(r.sub.age)",
            "MATH.ABS(r.sub.age)"
        };

        for (String expr : invalidExpressions) {
            try {
                ExpressionEvaluator.validateExpression(expr);
                fail("Invalid expression should throw exception: " + expr);
            } catch (IllegalArgumentException e) {
                // Expected to fail
                assertTrue("Error message should indicate non-standard operations",
                    e.getMessage().contains("non-standard Casbin operations"));
            }
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateExpression_NullExpression_ShouldFail() {
        ExpressionEvaluator.validateExpression(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateExpression_EmptyExpression_ShouldFail() {
        ExpressionEvaluator.validateExpression("");
    }

    @Test
    public void testEvaluateExpression_ValidExpression_ShouldEvaluate() {
        Map<String, Object> env = new HashMap<>();
        
        // Create a simple test object
        TestObject sub = new TestObject("alice", 25);
        env.put("r_sub", sub);

        // Test evaluation of a valid expression
        boolean result = ExpressionEvaluator.evaluateExpression("r_sub.age > 18", env, null);
        assertTrue("Expression should evaluate to true", result);

        result = ExpressionEvaluator.evaluateExpression("r_sub.name == 'alice'", env, null);
        assertTrue("Expression should evaluate to true", result);

        result = ExpressionEvaluator.evaluateExpression("r_sub.name == 'bob'", env, null);
        assertFalse("Expression should evaluate to false", result);
    }

    @Test
    public void testEvaluateExpression_InvalidExpression_ShouldReturnFalse() {
        Map<String, Object> env = new HashMap<>();
        
        try {
            ExpressionEvaluator.evaluateExpression("seq.list('A', 'B')", env, null);
            fail("Should throw IllegalArgumentException for invalid expression");
        } catch (IllegalArgumentException e) {
            // Expected
            assertTrue(e.getMessage().contains("non-standard Casbin operations"));
        }
    }

    @Test
    public void testConfigureRestrictedEvaluator_WithNull_ShouldReturnNull() {
        AviatorEvaluatorInstance result = ExpressionEvaluator.configureRestrictedEvaluator(null);
        assertNull("Should return null when input is null", result);
    }

    @Test
    public void testConfigureRestrictedEvaluator_WithInstance_ShouldConfigure() {
        AviatorEvaluatorInstance aviatorEval = AviatorEvaluator.newInstance();
        AviatorEvaluatorInstance result = ExpressionEvaluator.configureRestrictedEvaluator(aviatorEval);
        assertNotNull("Should return configured instance", result);
        assertSame("Should return same instance", aviatorEval, result);
    }

    // Test helper class
    public static class TestObject {
        private String name;
        private int age;

        public TestObject(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        public int getAge() {
            return age;
        }
    }
}
