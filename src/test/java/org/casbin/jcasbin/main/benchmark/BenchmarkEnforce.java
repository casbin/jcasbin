package org.casbin.jcasbin.main.benchmark;

import org.casbin.jcasbin.main.CachedEnforcer;
import org.casbin.jcasbin.main.Enforcer;
import org.openjdk.jmh.annotations.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.Throughput)
@State(Scope.Benchmark)
public class BenchmarkEnforce {

    @Param({
        "basic", 
        "rbac", 
        "rbac_with_domains", 
        "rbac_with_resource_roles", 
        "rbac_with_deny", 
        "keymatch", 
        "priority", 
        "abac"
    })
    private String modelType;

    @Param({"small", "medium", "large"})
    private String dataScale;

    @Param({"false", "true"})
    private boolean useCache;

    private Enforcer enforcer;
    private List<String[]> requests;
    private int requestCount;

    @Setup(Level.Trial)
    public void setup() {
        String modelPath = getModelPath(modelType);
        String policyPath = getPolicyPath(modelType);

        if (useCache) {
            enforcer = new CachedEnforcer(modelPath, "");
        } else {
            enforcer = new Enforcer(modelPath, "");
        }
        
        // Disable logging to keep JMH output clean
        enforcer.enableLog(false);
        
        enforcer.enableAutoBuildRoleLinks(false);

        if ("small".equals(dataScale)) {
             // Small: 1000 users, 100 roles (users/10), 10 resources (roles/10)
             // Aligned with Go benchmark "small" case
             generateDynamicData(1000); 
        } else if ("medium".equals(dataScale)) {
            generateDynamicData(10000);
        } else if ("large".equals(dataScale)) {
            generateDynamicData(100000);
        }

        enforcer.buildRoleLinks();

        requests = new ArrayList<>();
        requestCount = 1000;
        generateRequests();
    }

    private String getModelPath(String type) {
        switch (type) {
            case "basic": return "examples/basic_model.conf";
            case "rbac": return "examples/rbac_model.conf";
            case "rbac_with_domains": return "examples/rbac_with_domains_model.conf";
            case "rbac_with_resource_roles": return "examples/rbac_with_resource_roles_model.conf";
            case "rbac_with_deny": return "examples/rbac_with_deny_model.conf";
            case "keymatch": return "examples/keymatch_model.conf";
            case "priority": return "examples/priority_model.conf";
            case "abac": return "examples/abac_model.conf";
            default: return "examples/basic_model.conf";
        }
    }

    private String getPolicyPath(String type) {
        // Not used for loading file directly in this benchmark setup as we load manually/dynamically,
        // but useful for reference or if we switched to file loading.
        switch (type) {
            case "basic": return "examples/basic_policy.csv";
            case "rbac": return "examples/rbac_policy.csv";
            case "rbac_with_domains": return "examples/rbac_with_domains_policy.csv";
            case "rbac_with_resource_roles": return "examples/rbac_with_resource_roles_policy.csv";
            case "rbac_with_deny": return "examples/rbac_with_deny_policy.csv";
            case "keymatch": return "examples/keymatch_policy.csv";
            case "priority": return "examples/priority_policy.csv";
            case "abac": return ""; // ABAC usually has no policy file
            default: return "examples/basic_policy.csv";
        }
    }

    private void loadSmallData(String type) {
        switch (type) {
            case "basic":
                enforcer.addPolicy("alice", "data1", "read");
                enforcer.addPolicy("bob", "data2", "write");
                break;
            case "rbac":
                enforcer.addPolicy("alice", "data1", "read");
                enforcer.addPolicy("bob", "data2", "write");
                enforcer.addPolicy("data2_admin", "data2", "read");
                enforcer.addPolicy("data2_admin", "data2", "write");
                enforcer.addGroupingPolicy("alice", "data2_admin");
                break;
            case "rbac_with_domains":
                enforcer.addPolicy("admin", "domain1", "data1", "read");
                enforcer.addPolicy("admin", "domain1", "data1", "write");
                enforcer.addPolicy("admin", "domain2", "data2", "read");
                enforcer.addPolicy("admin", "domain2", "data2", "write");
                enforcer.addGroupingPolicy("alice", "admin", "domain1");
                enforcer.addGroupingPolicy("bob", "admin", "domain2");
                break;
            case "rbac_with_resource_roles":
                enforcer.addPolicy("alice", "data1", "read");
                enforcer.addPolicy("bob", "data2", "write");
                enforcer.addPolicy("data2_admin", "data2", "read");
                enforcer.addPolicy("data2_admin", "data2", "write");
                enforcer.addGroupingPolicy("alice", "data2_admin");
                enforcer.addGroupingPolicy("data1", "data_group"); // Resource role
                enforcer.addPolicy("data_group_admin", "data_group", "write"); 
                enforcer.addGroupingPolicy("alice", "data_group_admin");
                break;
            case "rbac_with_deny":
                enforcer.addPolicy("alice", "data1", "read");
                enforcer.addPolicy("bob", "data2", "write");
                enforcer.addPolicy("alice", "data2", "write", "deny"); // Deny rule
                break;
            case "keymatch":
                enforcer.addPolicy("alice", "/alice_data/*", "GET");
                enforcer.addPolicy("alice", "/alice_data/resource1", "POST");
                break;
            case "priority":
                enforcer.addPolicy("alice", "data1", "read");
                enforcer.addPolicy("data2_admin", "data2", "read");
                enforcer.addPolicy("data2_admin", "data2", "write");
                enforcer.addGroupingPolicy("alice", "data2_admin");
                // Priority logic usually depends on explicit priority field in policy or order
                // This model uses implicit order or explicit priority field?
                // examples/priority_model.conf uses explicit priority
                enforcer.addPolicy("10", "alice", "data1", "read", "allow");
                enforcer.addPolicy("20", "alice", "data1", "write", "deny");
                break;
            case "abac":
                // ABAC model often relies purely on request attributes matching logic
                break;
        }
    }

    private void generateDynamicData(int ruleCount) {
        int userCount = ruleCount; 
        int roleCount = ruleCount / 10;
        if (roleCount < 1) roleCount = 1;
        
        // p, role, res, act
        for (int i = 0; i < roleCount; i++) {
            if ("rbac_with_domains".equals(modelType)) {
                enforcer.addPolicy("group" + i, "domain1", "data" + (i % (roleCount/10 + 1)), "read");
            } else {
                enforcer.addPolicy("group" + i, "data" + (i % (roleCount/10 + 1)), "read");
            }
        }

        // g, user, role
        for (int i = 0; i < userCount; i++) {
            if ("rbac_with_domains".equals(modelType)) {
                enforcer.addGroupingPolicy("user" + i, "group" + (i % roleCount), "domain1");
            } else {
                enforcer.addGroupingPolicy("user" + i, "group" + (i % roleCount));
            }
        }
    }

    private void generateRequests() {
        for (int i = 0; i < requestCount; i++) {
            String sub, obj, act;
            boolean expectAllow = (i % 2 == 0);

            // Calculate scale parameters for dynamic generation
            // Small: 1000 users, Medium: 10000, Large: 100000
            int totalUsers = "small".equals(dataScale) ? 1000 : 
                             ("medium".equals(dataScale) ? 10000 : 100000);
            
            // Generate request based on scale
            int userIdx = i % totalUsers;
            
            if (expectAllow) {
                // Role count is users / 10
                int roleCount = totalUsers / 10;
                // Ensure at least 1 role
                if (roleCount < 1) roleCount = 1;
                
                int groupIdx = userIdx % roleCount;
                // Resource count is roles / 10 (or users / 100)
                // Logic in generateDynamicData: obj = "data" + (i % (roleCount/10 + 1))
                // We must match that logic to hit a policy
                int dataIdx = groupIdx % (roleCount/10 + 1);
                
                sub = "user" + userIdx;
                obj = "data" + dataIdx;
                act = "read";
            } else {
                sub = "user" + userIdx;
                obj = "data_invalid";
                act = "read";
            }

            if ("rbac_with_domains".equals(modelType)) {
                requests.add(new String[]{sub, "domain1", obj, act});
            } else {
                requests.add(new String[]{sub, obj, act});
            }
        }
    }
    
    @State(Scope.Thread)
    public static class RequestIndex {
        int index = 0;
    }

    @Benchmark
    public void enforce(RequestIndex state, org.openjdk.jmh.infra.Blackhole bh) {
        String[] req = requests.get(state.index);
        state.index = (state.index + 1) % requestCount;
        
        // Enforce with variable arguments
        if (req.length == 3) {
            bh.consume(enforcer.enforce(req[0], req[1], req[2]));
        } else if (req.length == 4) {
            bh.consume(enforcer.enforce(req[0], req[1], req[2], req[3]));
        }
    }
}
