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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ExpressionValidator validates expressions to ensure they only use standard Casbin syntax
 * and don't expose aviatorscript-specific features that would break cross-platform compatibility.
 */
public class ExpressionValidator {
    
    // Patterns for aviatorscript-specific syntax that should be blocked
    private static final Pattern[] DISALLOWED_PATTERNS = {
        Pattern.compile("\\bseq\\."),           // seq.list(), seq.map(), etc.
        Pattern.compile("\\bstring\\."),        // string.startsWith(), string.endsWith(), etc.
        Pattern.compile("\\bmath\\."),          // math.sqrt(), math.pow(), etc.
        Pattern.compile("\\blambda\\b"),        // lambda expressions
        Pattern.compile("\\blet\\b"),           // variable binding
        Pattern.compile("\\bfn\\b"),            // function definitions
        Pattern.compile("->"),                  // lambda arrow
        Pattern.compile("=>"),                  // alternative lambda arrow
        Pattern.compile("\\bfor\\b"),           // for loops
        Pattern.compile("\\bwhile\\b"),         // while loops
        Pattern.compile("\\breturn\\b"),        // return statements
        Pattern.compile("\\bif\\b.*\\bthen\\b.*\\belse\\b"), // if-then-else (aviator style)
        Pattern.compile("\\?:"),                // ternary operator (aviator uses different syntax)
    };
    
    /**
     * Validates that an expression only uses standard Casbin syntax.
     * 
     * @param expression the expression to validate
     * @throws IllegalArgumentException if the expression contains non-standard syntax
     */
    public static void validateExpression(String expression) {
        if (expression == null || expression.isEmpty()) {
            return;
        }
        
        // Check for disallowed aviatorscript-specific patterns
        for (Pattern pattern : DISALLOWED_PATTERNS) {
            Matcher matcher = pattern.matcher(expression);
            if (matcher.find()) {
                throw new IllegalArgumentException(
                    "Expression contains non-standard syntax: '" + matcher.group() + 
                    "'. This aviatorscript-specific feature is not part of Casbin's standard specification."
                );
            }
        }
    }
}
