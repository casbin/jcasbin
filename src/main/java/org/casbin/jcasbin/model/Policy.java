package org.casbin.jcasbin.model;

import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Policy {
    Map<String, Map<String, Assertion>> model;

    /**
     * buildRoleLinks initializes the roles in RBAC.
     */
    public void buildRoleLinks(RoleManager rm) {
        for (Assertion ast : this.model.get("g").values()) {
            ast.buildRoleLinks(rm);
        }
    }

    /**
     * printPolicy prints the policy to log.
     */
    public void printPolicy() {
        Util.logPrint("Policy:");
        for (Map.Entry<String, Assertion> entry : model.get("p").entrySet()) {
            String key = entry.getKey();
            Assertion ast = entry.getValue();
            Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
        }

        for (Map.Entry<String, Assertion> entry : model.get("g").entrySet()) {
            String key = entry.getKey();
            Assertion ast = entry.getValue();
            Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
        }
    }

    /**
     * clearPolicy clears all current policy.
     */
    public void clearPolicy() {
        for (Assertion ast : model.get("p").values()) {
            ast.policy = null;
        }

        for (Assertion ast : model.get("g").values()) {
            ast.policy = null;
        }
    }

    /**
     * getPolicy gets all rules in a policy.
     */
    public List<List<String>> getPolicy(String sec, String ptype) {
        return this.model.get(sec).get(ptype).policy;
    }

    /**
     * getFilteredPolicy gets rules based on field filters from a policy.
     */
    public List<List<String>> getFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> res = new ArrayList<>();

        for (List<String> rule : this.model.get(sec).get(ptype).policy) {
            boolean matched = true;
            for (int i = 0; i < fieldValues.length; i ++) {
                String fieldValue = fieldValues[i];
                if (!fieldValue.equals("") && !rule.get(fieldIndex + i).equals(fieldValue)) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                res.add(rule);
            }
        }

        return res;
    }

    /**
     * hasPolicy determines whether a model has the specified policy rule.
     */
    public boolean hasPolicy(String sec, String ptype, List<String> rule) {
        for (List<String> r : model.get(sec).get(ptype).policy) {
            if (Util.arrayEquals(rule, r)) {
                return true;
            }
        }

        return false;
    }

    /**
     * addPolicy adds a policy rule to the model.
     */
    public boolean addPolicy(String sec, String ptype, List<String> rule) {
        if (!this.hasPolicy(sec, ptype, rule)) {
            this.model.get(sec).get(ptype).policy.add(rule);
            return true;
        }
        return false;
    }

    /**
     * removePolicy removes a policy rule from the model.
     */
    public boolean removePolicy(String sec, String ptype, List<String> rule) {
        for (int i = 0; i < this.model.get(sec).get(ptype).policy.size(); i ++) {
            List<String> r = this.model.get(sec).get(ptype).policy.get(i);
            if (Util.arrayEquals(rule, r)) {
                this.model.get(sec).get(ptype).policy.remove(i);
                return true;
            }
        }

        return false;
    }

    /**
     * removeFilteredPolicy removes policy rules based on field filters from the model.
     */
    public boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> tmp = new ArrayList<>();
        boolean res = false;

        for (List<String> rule : this.model.get(sec).get(ptype).policy) {
            boolean matched = true;
            for (int i = 0; i < fieldValues.length; i ++) {
                String fieldValue = fieldValues[i];
                if (!fieldValue.equals("") && !rule.get(fieldIndex + i).equals(fieldValue)) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                res = true;
            } else {
                tmp.add(rule);
            }
        }

        this.model.get(sec).get(ptype).policy = tmp;
        return res;
    }

    /**
     * getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
     */
    public List<String> getValuesForFieldInPolicy(String sec, String ptype, int fieldIndex) {
        List<String> values = new ArrayList<>();

        for (List<String> rule : this.model.get(sec).get(ptype).policy) {
            values.add(rule.get(fieldIndex));
        }

        Util.arrayRemoveDuplicates(values);

        return values;
    }
}
