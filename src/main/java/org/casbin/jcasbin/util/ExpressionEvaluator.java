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

package org.casbin.jcasbin.util;

import com.googlecode.aviator.AviatorEvaluatorInstance;
import com.googlecode.aviator.Options;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * ExpressionEvaluator provides a sandboxed expression evaluator for Casbin.
 * It restricts expressions to only standard Casbin operations, preventing the use
 * of aviatorscript-specific features that would break cross-platform compatibility.
 * 
 * @author casbin team
 */
public class ExpressionEvaluator {
    
    // Pattern to detect potentially unsafe aviatorscript-specific features
    private static final Pattern UNSAFE_PATTERN = Pattern.compile(
        "(?:seq\\.|string\\.|math\\.|" + // aviatorscript namespace calls
        "include\\(\\s*seq\\.list|" +    // aviatorscript collection operations
        "lambda\\(|" +                     // lambda expressions
        "let\\s+|" +                       // let bindings
        "\\bfn\\s+|" +                     // function definitions
        "\\bfor\\s*\\(|" +                 // for loops
        "\\bwhile\\s*\\(|" +               // while loops
        "\\bnew\\s+|" +                    // object instantiation
        "\\bimport\\s+)"                   // imports
    );
    
    /**
     * Validates that an expression only contains standard Casbin operations.
     * 
     * @param expression the expression to validate
     * @throws IllegalArgumentException if the expression contains unsafe operations
     */
    public static void validateExpression(String expression) {
        if (expression == null || expression.isEmpty()) {
            throw new IllegalArgumentException("Expression cannot be null or empty");
        }
        
        if (UNSAFE_PATTERN.matcher(expression).find()) {
            throw new IllegalArgumentException(
                "Expression contains non-standard Casbin operations. " +
                "Please use only standard operators and registered functions. " +
                "Expression: " + expression
            );
        }
    }
    
    /**
     * Configures an AviatorEvaluatorInstance with restricted options for safe evaluation.
     * This disables features that go beyond standard Casbin expression evaluation.
     * 
     * @param aviatorEval the evaluator instance to configure
     * @return the configured evaluator instance
     */
    public static AviatorEvaluatorInstance configureRestrictedEvaluator(AviatorEvaluatorInstance aviatorEval) {
        if (aviatorEval == null) {
            return null;
        }
        
        // Disable feature/function assignment in runtime for security
        aviatorEval.setOption(Options.FEATURE_SET, com.googlecode.aviator.Feature.asSet());
        
        // Use optimized mode
        aviatorEval.setOption(Options.OPTIMIZE_LEVEL, com.googlecode.aviator.AviatorEvaluator.EVAL);
        
        return aviatorEval;
    }
    
    /**
     * Safely evaluates an expression with validation.
     * 
     * @param expression the expression to evaluate
     * @param env the evaluation environment containing variables
     * @param aviatorEval the aviator evaluator instance (can be null)
     * @return the evaluation result
     * @throws IllegalArgumentException if the expression is invalid
     */
    public static boolean evaluateExpression(String expression, Map<String, Object> env, AviatorEvaluatorInstance aviatorEval) {
        // Validate expression first
        validateExpression(expression);
        
        // Evaluate using the existing BuiltInFunctions.eval method
        return BuiltInFunctions.eval(expression, env, aviatorEval);
    }
}
