package org.casbin.jcasbin.main.benchmark;

import org.casbin.jcasbin.main.Enforcer;
import org.openjdk.jmh.annotations.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.SingleShotTime)
@State(Scope.Benchmark)
public class BenchmarkMemory {

    @Param({
        "ACL", 
        "RBAC", 
        "RBAC_Medium", 
        "RBAC_Large", 
        "RBAC_With_Domains", 
        "Priority", 
        "ABAC_Complex"
    })
    private String scenario;

    private Enforcer enforcer;

    @Benchmark
    public long measureMemory() {
        // Force GC before
        forceGC();
        long initialMemory = getUsedMemory();

        if ("ACL".equals(scenario)) {
            // "ACL/Basic: 2 rules, 2 users"
            enforcer = new Enforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        } else if ("RBAC".equals(scenario)) {
            enforcer = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        } else if ("RBAC_Medium".equals(scenario)) {
            // "Medium (10k rules)"
            enforcer = new Enforcer("examples/rbac_model.conf", "");
            enforcer.enableLog(false);
            enforcer.enableAutoBuildRoleLinks(false);
            generateDynamicData(enforcer, 10000);
            enforcer.buildRoleLinks();
        } else if ("RBAC_Large".equals(scenario)) {
            // "Large (100k rules, 10k roles)"
            enforcer = new Enforcer("examples/rbac_model.conf", "");
            enforcer.enableLog(false);
            enforcer.enableAutoBuildRoleLinks(false);
            generateDynamicData(enforcer, 100000);
            enforcer.buildRoleLinks();
        } else if ("RBAC_With_Domains".equals(scenario)) {
            enforcer = new Enforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv");
        } else if ("Priority".equals(scenario)) {
            enforcer = new Enforcer("examples/priority_model.conf", "examples/priority_policy.csv");
        } else if ("ABAC_Complex".equals(scenario)) {
             // "ABAC: attribute calculation" - usually 0 rules, just model
             enforcer = new Enforcer("examples/abac_model.conf", "");
        } else {
             // Fallback/Default
             enforcer = new Enforcer();
        }
        
        enforcer.enableLog(false);

        // Force GC after
        forceGC();
        long finalMemory = getUsedMemory();
        
        return finalMemory - initialMemory;
    }

    private void generateDynamicData(Enforcer e, int ruleCount) {
        int userCount = ruleCount;
        int roleCount = ruleCount / 10;
        if (roleCount < 1) roleCount = 1;

        List<List<String>> pRules = new ArrayList<>();
        for (int i = 0; i < roleCount; i++) {
            List<String> line = new ArrayList<>();
            line.add("group" + i);
            line.add("data" + (i % (roleCount/10 + 1)));
            line.add("read");
            pRules.add(line);
        }
        e.addPolicies(pRules);

        List<List<String>> gRules = new ArrayList<>();
        for (int i = 0; i < userCount; i++) {
            List<String> line = new ArrayList<>();
            line.add("user" + i);
            line.add("group" + (i % roleCount));
            gRules.add(line);
        }
        e.addGroupingPolicies(gRules);
    }

    private long getUsedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private void forceGC() {
        for (int i = 0; i < 3; i++) {
            System.gc();
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
            }
        }
    }
}
