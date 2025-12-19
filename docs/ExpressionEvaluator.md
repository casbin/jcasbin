# Expression Evaluator - Cross-Platform Compatible eval() Function

## Overview

The `ExpressionEvaluator` class provides a sandboxed expression evaluator for Casbin's `eval()` function. It ensures that expressions only use standard Casbin operations, preventing the use of aviatorscript-specific features that would break cross-platform compatibility.

## Problem Statement

The previous implementation of `eval()` directly used aviatorscript, which allowed the use of aviatorscript-specific syntax such as:
- `seq.list('A', 'B')` - Collection operations
- `string.startsWith()`, `string.endsWith()` - String namespace methods
- `math.abs()` - Math namespace functions
- `lambda()`, `fn()` - Function definitions
- `let`, `for`, `while` - Control flow statements

These features are:
1. **Not portable** across different Casbin implementations (Go, Node.js, Python, etc.)
2. **Security risks** as they expose operations beyond Casbin's specification
3. **Non-standard** and not part of the official Casbin expression syntax

## Solution

The `ExpressionEvaluator` validates expressions before evaluation to ensure they only contain standard Casbin operations.

## Allowed Expression Syntax

The following operations are allowed in `eval()` expressions:

### 1. Property Access
Access object properties using dot notation:
```java
r.sub.name
r.sub.age
r.obj.owner
p.sub_rule
```

### 2. Comparison Operators
```java
r.sub.age > 18
r.sub.age >= 18
r.sub.age < 60
r.sub.age <= 60
r.sub.name == 'alice'
r.sub.name != 'bob'
```

### 3. Logical Operators
```java
r.sub.age > 18 && r.sub.age < 60
r.sub.name == 'alice' || r.sub.name == 'bob'
!r.sub.isBlocked
```

### 4. Arithmetic Operators
```java
r.sub.age + 10 > 28
r.sub.age * 2 < 100
r.sub.score - 10 >= 80
r.sub.total / 2 > 50
r.sub.value % 10 == 0
```

### 5. Literals
- **String literals**: Use single quotes `'alice'`, `'data1'`
- **Number literals**: `18`, `60`, `3.14`
- **Boolean literals**: `true`, `false`

### 6. Registered Function Calls
Custom functions registered with the enforcer can be called:
```java
custom(r.obj)
keyMatch(r.sub, '/api/*')
regexMatch(r.obj, '^/data\\d+$')
```

## Blocked Operations

The following aviatorscript-specific operations are **NOT allowed** and will cause validation to fail:

### Namespace Operations
```java
seq.list('A', 'B')           // ❌ Blocked
string.startsWith(r.obj, '/') // ❌ Blocked
math.abs(r.sub.age)          // ❌ Blocked
```

### Function Definitions
```java
fn add(a, b) { return a + b } // ❌ Blocked
lambda(x) -> x + 1             // ❌ Blocked
```

### Control Flow
```java
let x = 10                     // ❌ Blocked
for (i = 0; i < 10; i++)       // ❌ Blocked
while (true)                   // ❌ Blocked
```

### Object Instantiation and Imports
```java
new java.util.ArrayList()      // ❌ Blocked
import java.util.List          // ❌ Blocked
```

## Usage

### In Policy Rules

Define expressions in your policy files that will be evaluated:

**Model** (`abac_rule_model.conf`):
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub_rule, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = eval(p.sub_rule) && r.obj == p.obj && r.act == p.act
```

**Policy** (`abac_rule_policy.csv`):
```csv
p, r.sub.Age > 18, /data1, read
p, r.sub.Age < 60, /data2, write
```

### In Java Code

```java
import org.casbin.jcasbin.main.Enforcer;

// Create enforcer
Enforcer enforcer = new Enforcer("model.conf", "policy.csv");

// Create request subject with attributes
class User {
    private String name;
    private int age;
    // getters...
}

User alice = new User("alice", 25);

// Enforce - the eval() function will be called with the expression from policy
boolean allowed = enforcer.enforce(alice, "/data1", "read");
// Returns true because alice.age (25) > 18
```

## Implementation Details

### ExpressionEvaluator Class

The `ExpressionEvaluator` class provides:

1. **validateExpression(String expression)**: Validates that an expression only contains standard Casbin operations
2. **evaluateExpression(String expression, Map<String, Object> env, AviatorEvaluatorInstance aviatorEval)**: Validates and evaluates an expression
3. **configureRestrictedEvaluator(AviatorEvaluatorInstance aviatorEval)**: Configures an aviator evaluator with restricted options

### EvalFunc Integration

The `EvalFunc` class (the wrapper for the `eval()` function) has been updated to use `ExpressionEvaluator`:

```java
@Override
public AviatorObject call(Map<String, Object> env, AviatorObject arg1) {
    String eval = FunctionUtils.getStringValue(arg1, env);
    eval = replaceTargets(eval, env);
    
    // Validate expression to ensure it only uses standard Casbin operations
    try {
        ExpressionEvaluator.validateExpression(eval);
    } catch (IllegalArgumentException e) {
        Util.logPrintfWarn("Invalid eval expression: {}", e.getMessage());
        return AviatorBoolean.valueOf(false);
    }
    
    return AviatorBoolean.valueOf(BuiltInFunctions.eval(eval, env, getAviatorEval()));
}
```

## Error Handling

When an invalid expression is detected:

1. An `IllegalArgumentException` is thrown with a descriptive error message
2. The error is logged as a warning
3. The evaluation returns `false` to fail safely

Example error message:
```
Expression contains non-standard Casbin operations. 
Please use only standard operators and registered functions. 
Expression: seq.list('A', 'B')
```

## Migration Guide

### For Existing Code

If your existing policies use standard Casbin syntax (property access, comparison operators, logical operators), **no changes are needed**. The validator allows all standard operations.

### If Using Aviatorscript-Specific Features

If you have policies that use aviatorscript-specific features, you need to migrate them:

**Before** (aviatorscript-specific):
```csv
p, include(seq.list('admin', 'moderator'), r.sub.role), /data1, read
p, string.startsWith(r.obj, '/api'), /api, GET
```

**After** (standard Casbin):
```csv
p, r.sub.role == 'admin' || r.sub.role == 'moderator', /data1, read
p, keyMatch(r.obj, '/api/*'), /api, GET
```

Or use registered custom functions for complex logic:
```java
// Register a custom function
enforcer.addFunction("checkRole", new CustomRoleFunction());
```

## Testing

Comprehensive tests are provided in `ExpressionEvaluatorTest.java`:

- Tests for valid standard Casbin expressions
- Tests for invalid aviatorscript-specific features
- Tests for null/empty expressions
- Integration tests with actual evaluation

Run tests:
```bash
mvn test -Dtest=ExpressionEvaluatorTest
```

## Benefits

1. **Cross-Platform Compatibility**: Expressions work the same way across all Casbin implementations
2. **Security**: Prevents execution of arbitrary code beyond Casbin specification
3. **Portability**: Policies can be easily migrated between different platforms
4. **Clarity**: Clear definition of what operations are allowed in expressions
5. **Backward Compatibility**: Existing standard expressions continue to work without changes

## References

- [Casbin Documentation](https://casbin.org/docs/)
- [ABAC Model Documentation](https://casbin.org/docs/abac)
- [Expression Syntax](https://casbin.org/docs/syntax-for-models)
