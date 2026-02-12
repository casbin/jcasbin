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

import org.casbin.jcasbin.util.ExpressionValidator;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ExpressionValidatorTest {

    @Test
    public void testValidStandardCasbinExpressions() {
        // Standard operators and comparisons should be allowed
        ExpressionValidator.validateExpression("r_sub == p_sub");
        ExpressionValidator.validateExpression("r_sub == p_sub && r_obj == p_obj");
        ExpressionValidator.validateExpression("r_sub == p_sub || r_obj == p_obj");
        ExpressionValidator.validateExpression("r_age > 18");
        ExpressionValidator.validateExpression("r_age >= 18 && r_age < 65");
        ExpressionValidator.validateExpression("r_status != 'banned'");
        
        // Arithmetic should be allowed
        ExpressionValidator.validateExpression("r_price * 1.1 > p_threshold");
        ExpressionValidator.validateExpression("r_count + p_offset < 100");
        ExpressionValidator.validateExpression("r_value - p_discount >= 0");
        ExpressionValidator.validateExpression("r_total / r_count > 50");
        
        // Negation should be allowed
        ExpressionValidator.validateExpression("!r_disabled");
        ExpressionValidator.validateExpression("!(r_sub == p_sub)");
    }

    @Test
    public void testValidCasbinBuiltInFunctions() {
        // All standard Casbin functions should be allowed
        ExpressionValidator.validateExpression("g(r_sub, p_sub)");
        ExpressionValidator.validateExpression("g2(r_sub, p_sub, r_domain)");
        ExpressionValidator.validateExpression("keyMatch(r_path, p_path)");
        ExpressionValidator.validateExpression("keyMatch2(r_path, p_path)");
        ExpressionValidator.validateExpression("keyMatch3(r_path, p_path)");
        ExpressionValidator.validateExpression("keyMatch4(r_path, p_path)");
        ExpressionValidator.validateExpression("keyMatch5(r_path, p_path)");
        ExpressionValidator.validateExpression("keyGet(r_path, p_path)");
        ExpressionValidator.validateExpression("keyGet2(r_path, p_path, 'id')");
        ExpressionValidator.validateExpression("regexMatch(r_path, p_pattern)");
        ExpressionValidator.validateExpression("ipMatch(r_ip, p_cidr)");
        ExpressionValidator.validateExpression("globMatch(r_path, p_glob)");
        ExpressionValidator.validateExpression("allMatch(r_key, p_key)");
        ExpressionValidator.validateExpression("timeMatch(r_time, p_time)");
        ExpressionValidator.validateExpression("eval(p_rule)");
        
        // Include and tuple are used for "in" operator conversion
        ExpressionValidator.validateExpression("include(r_obj, r_sub)");
        ExpressionValidator.validateExpression("include(tuple('admin', 'editor'), r_role)");
        
        // Custom functions should be allowed (users can register them)
        ExpressionValidator.validateExpression("customFunc(r_sub, p_sub)");
        ExpressionValidator.validateExpression("myFunction(r_value)");
    }

    @Test
    public void testValidComplexExpressions() {
        // Complex combinations should be allowed
        ExpressionValidator.validateExpression("g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act");
        ExpressionValidator.validateExpression("g(r_sub, p_sub) && keyMatch(r_path, p_path)");
        ExpressionValidator.validateExpression("eval(p_sub_rule) && r_obj == p_obj");
        ExpressionValidator.validateExpression("r_age > 18 && include(tuple('read', 'write'), r_act)");
        ExpressionValidator.validateExpression("r_sub.age >= 18 && custom(r_obj)");
    }

    @Test
    public void testDisallowedAviatorScriptSequenceMethods() {
        // seq.list() should be disallowed
        try {
            ExpressionValidator.validateExpression("seq.list('A', 'B')");
            fail("Should have thrown IllegalArgumentException for seq.list()");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("seq."));
            assertTrue(e.getMessage().contains("aviatorscript-specific"));
        }
        
        // seq.map() should be disallowed
        try {
            ExpressionValidator.validateExpression("seq.map(r_items, lambda(x) -> x * 2)");
            fail("Should have thrown IllegalArgumentException for seq.map()");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("seq."));
        }
    }

    @Test
    public void testDisallowedAviatorScriptStringMethods() {
        // string.startsWith() should be disallowed
        try {
            ExpressionValidator.validateExpression("string.startsWith(r_path, '/admin')");
            fail("Should have thrown IllegalArgumentException for string.startsWith()");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("string."));
            assertTrue(e.getMessage().contains("aviatorscript-specific"));
        }
        
        // string.endsWith() should be disallowed
        try {
            ExpressionValidator.validateExpression("string.endsWith(r_path, '.pdf')");
            fail("Should have thrown IllegalArgumentException for string.endsWith()");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("string."));
        }
        
        // string.substring() should be disallowed
        try {
            ExpressionValidator.validateExpression("string.substring(r_path, 0, 5)");
            fail("Should have thrown IllegalArgumentException for string.substring()");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("string."));
        }
    }

    @Test
    public void testDisallowedAviatorScriptMathMethods() {
        // math.sqrt() should be disallowed
        try {
            ExpressionValidator.validateExpression("math.sqrt(r_value) > 10");
            fail("Should have thrown IllegalArgumentException for math.sqrt()");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("math."));
            assertTrue(e.getMessage().contains("aviatorscript-specific"));
        }
        
        // math.pow() should be disallowed
        try {
            ExpressionValidator.validateExpression("math.pow(r_base, 2)");
            fail("Should have thrown IllegalArgumentException for math.pow()");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("math."));
        }
    }

    @Test
    public void testDisallowedLambdaExpressions() {
        // Lambda with arrow should be disallowed
        try {
            ExpressionValidator.validateExpression("lambda(x) -> x * 2");
            fail("Should have thrown IllegalArgumentException for lambda");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("lambda") || e.getMessage().contains("->"));
        }
        
        // Alternative lambda syntax should be disallowed
        try {
            ExpressionValidator.validateExpression("(x) => x * 2");
            fail("Should have thrown IllegalArgumentException for lambda arrow");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("=>"));
        }
    }

    @Test
    public void testDisallowedControlStructures() {
        // for loops should be disallowed
        try {
            ExpressionValidator.validateExpression("for x in r_items { x * 2 }");
            fail("Should have thrown IllegalArgumentException for 'for'");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("for"));
        }
        
        // while loops should be disallowed
        try {
            ExpressionValidator.validateExpression("while x < 10 { x = x + 1 }");
            fail("Should have thrown IllegalArgumentException for 'while'");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("while"));
        }
        
        // if-then-else (Aviator style) should be disallowed
        try {
            ExpressionValidator.validateExpression("if r_age > 18 then 'adult' else 'minor'");
            fail("Should have thrown IllegalArgumentException for 'if-then-else'");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("if") || e.getMessage().contains("then") || e.getMessage().contains("else"));
        }
    }

    @Test
    public void testDisallowedVariableBindingAndFunctions() {
        // let variable binding should be disallowed
        try {
            ExpressionValidator.validateExpression("let x = 10; x * 2");
            fail("Should have thrown IllegalArgumentException for 'let'");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("let"));
        }
        
        // function definitions should be disallowed
        try {
            ExpressionValidator.validateExpression("fn add(a, b) { a + b }");
            fail("Should have thrown IllegalArgumentException for 'fn'");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("fn"));
        }
        
        // return statements should be disallowed
        try {
            ExpressionValidator.validateExpression("return r_value * 2");
            fail("Should have thrown IllegalArgumentException for 'return'");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("return"));
        }
    }

    @Test
    public void testNullAndEmptyExpressions() {
        // Null and empty expressions should be allowed (no validation needed)
        ExpressionValidator.validateExpression(null);
        ExpressionValidator.validateExpression("");
        ExpressionValidator.validateExpression("   ");
    }
}
