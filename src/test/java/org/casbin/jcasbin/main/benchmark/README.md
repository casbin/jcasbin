# JCasbin Benchmark Suite

This directory contains the official JCasbin benchmark suite aligned with [go-casbin](https://github.com/casbin/casbin) standard benchmark scenarios.

## Overview

The benchmark suite tests authorization performance across different Casbin models and data scales. All benchmarks use deterministic data generation to ensure reproducible results across runs.

## Benchmark Scenarios

The following standard scenarios are implemented:

| Scenario | Rules | Users | Roles | Resources/Domains | Description |
|----------|-------|-------|-------|------------------|-------------|
| **ACL** | 2 | 2 | - | - | Basic Access Control List |
| **RBAC** | 5 | 2 | 1 | - | Basic Role-Based Access Control |
| **RBAC Small** | 1,100 | 1,000 | 100 | 10 | Small-scale RBAC |
| **RBAC Medium** | 11,000 | 10,000 | 1,000 | 100 | Medium-scale RBAC |
| **RBAC Large** | 110,000 | 100,000 | 10,000 | 1,000 | Large-scale RBAC |
| **RBAC with Resource Roles** | 6 | 2 | 2 | - | RBAC with resource grouping |
| **RBAC with Domains** | 6 | 2 | 1 | 2 domains | Multi-tenant RBAC |
| **ABAC** | 0 | 0 | - | - | Attribute-Based Access Control |
| **RESTful/KeyMatch** | 5 | 3 | - | - | REST API pattern matching |
| **Deny-override** | 6 | 2 | 1 | - | RBAC with explicit deny |
| **Priority** | 9 | 2 | 2 | - | Priority-based authorization |

## Running Benchmarks

### Prerequisites

- JDK 8 or higher
- Maven 3.x

### Running All Benchmarks

```bash
# Using Maven
mvn clean test-compile exec:java -Dexec.mainClass="org.openjdk.jmh.Main" -Dexec.classpathScope=test

# Or build and run JMH benchmark JAR
mvn clean package
java -jar target/benchmarks.jar
```

### Running a Specific Benchmark

```bash
# Run a single benchmark class
mvn clean test-compile exec:java -Dexec.mainClass="org.casbin.jcasbin.main.benchmark.BenchmarkBasicModel" -Dexec.classpathScope=test

# Or using JMH pattern matching
java -jar target/benchmarks.jar BenchmarkBasicModel
```

### Recommended JMH Parameters

All benchmarks are configured with the following recommended parameters to match go-casbin benchmark behavior:

```
-f 2    # 2 forks
-wi 3   # 3 warmup iterations
-i 5    # 5 measurement iterations
-t 1    # 1 thread
```

These can be overridden when running benchmarks:

```bash
java -jar target/benchmarks.jar -f 1 -wi 5 -i 10
```

## Benchmark Classes

### BenchmarkBasicModel (ACL)
- **File**: `BenchmarkBasicModel.java`
- **Model**: ACL (Access Control List)
- **Scale**: 2 rules, 2 users
- **Test**: `enforce("alice", "data1", "read")`

### BenchmarkRBACModelSingle (RBAC)
- **File**: `BenchmarkRBACModelSingle.java`
- **Model**: Basic RBAC
- **Scale**: 5 rules (4 policies + 1 role assignment), 2 users, 1 role
- **Test**: `enforce("alice", "data2", "read")`

### BenchmarkRBACModelSmall
- **File**: `BenchmarkRBACModelSmall.java`
- **Model**: RBAC with small dataset
- **Scale**: 1,100 rules, 1,000 users, 100 roles, 10 resources
- **Test**: `enforce("user501", "data9", "read")`
- **Generation**: Every 10 roles → 1 resource, Every 10 users → 1 role

### BenchmarkRBACModelMedium
- **File**: `BenchmarkRBACModelMedium.java`
- **Model**: RBAC with medium dataset
- **Scale**: 11,000 rules, 10,000 users, 1,000 roles, 100 resources
- **Test**: `enforce("user5001", "data150", "read")`
- **Generation**: Every 10 roles → 1 resource, Every 10 users → 1 role

### BenchmarkRBACModelLarge
- **File**: `BenchmarkRBACModelLarge.java`
- **Model**: RBAC with large dataset
- **Scale**: 110,000 rules, 100,000 users, 10,000 roles, 1,000 resources
- **Test**: `enforce("user50001", "data1500", "read")`
- **Generation**: Every 10 roles → 1 resource, Every 10 users → 1 role

### BenchmarkRBACModelWithResourceRoles
- **File**: `BenchmarkRBACModelWithResourceRoles.java`
- **Model**: RBAC with resource roles
- **Scale**: 6 rules, 2 users, 2 roles
- **Test**: `enforce("alice", "data1", "read")`

### BenchmarkRBACModelWithDomains
- **File**: `BenchmarkRBACModelWithDomains.java`
- **Model**: RBAC with multi-tenancy
- **Scale**: 6 rules, 2 users, 1 role, 2 domains
- **Test**: `enforce("alice", "domain1", "data1", "read")`

### BenchmarkABACModel
- **File**: `BenchmarkABACModel.java`
- **Model**: ABAC (Attribute-Based Access Control)
- **Scale**: 0 rules (attribute-based logic in model)
- **Test**: `enforce("alice", data1, "read")`

### BenchmarkKeyMatchModel (RESTful)
- **File**: `BenchmarkKeyMatchModel.java`
- **Model**: RESTful with pattern matching
- **Scale**: 5 rules, 3 users
- **Test**: `enforce("alice", "/alice_data/resource1", "GET")`

### BenchmarkRBACModelWithDeny (Deny-override)
- **File**: `BenchmarkRBACModelWithDeny.java`
- **Model**: RBAC with explicit deny
- **Scale**: 6 rules (5 policies + 1 role assignment), 2 users, 1 role
- **Test**: `enforce("alice", "data1", "read")`

### BenchmarkPriorityModel
- **File**: `BenchmarkPriorityModel.java`
- **Model**: Priority-based authorization
- **Scale**: 9 rules (7 policies + 2 role assignments), 2 users, 2 roles
- **Test**: `enforce("alice", "data1", "read")`

## Deterministic Data Generation

All benchmarks use deterministic policy generation to ensure identical results across runs:

- No randomness in data generation
- Loop counters use integer division for predictable patterns
- Static initialization blocks generate policies before benchmarking
- User/role/resource names follow consistent patterns: `user{i}`, `group{i}`, `data{i}`

Example from RBAC Small:
```java
// 100 roles, 10 resources
for (int i = 0; i < 100; i++) {
    e.addPolicy(String.format("group%d", i), String.format("data%d", i/10), "read");
}
// 1000 users
for (int i = 0; i < 1000; i++) {
    e.addGroupingPolicy(String.format("user%d", i), String.format("group%d", i/10));
}
```

## JMH Configuration

All benchmarks use the following JMH annotations:

```java
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
@Threads(1)
```

This configuration measures average execution time per operation in milliseconds, similar to Go's `ns/op` metric.

## Comparison with go-casbin

These benchmarks are designed to be directly comparable with [go-casbin benchmarks](https://github.com/casbin/casbin/tree/master/benchmarks):

- Identical data scales
- Same policy generation logic
- Same test cases (user, resource, action)
- Consistent naming conventions

This allows for fair performance comparisons between JCasbin and go-casbin implementations.

## Contributing

When adding new benchmarks:

1. Follow the naming convention: `Benchmark<Scenario>.java`
2. Add comprehensive Javadoc with:
   - Scenario description
   - Data scale details
   - Policy structure
   - Test case
   - Recommended JMH options
3. Use deterministic data generation (no randomness)
4. Use standard JMH parameters: `-f 2 -wi 3 -i 5 -t 1`
5. Update this README with the new benchmark details

## References

- [Casbin Official Documentation](https://casbin.org/docs/en/overview)
- [go-casbin Benchmarks](https://github.com/casbin/casbin/tree/master/benchmarks)
- [JMH Documentation](https://github.com/openjdk/jmh)
- [Casbin Performance Monitor](https://casbin.org/docs/en/benchmark)
