// Copyright 2018 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.model;

import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Policy {
    public Map<String, Map<String, Assertion>> model;

    /**
     * buildRoleLinks initializes the roles in RBAC.
     *
     * @param rm the role manager.
     */
    public void buildRoleLinks(RoleManager rm) {
        if (model.containsKey("g")) {
            for (Assertion ast : model.get("g").values()) {
                ast.buildRoleLinks(rm);
            }
        }
    }

    /**
     * printPolicy prints the policy to log.
     */
    public void printPolicy() {
        Util.logPrint("Policy:");
        if (model.containsKey("p")) {
            for (Map.Entry<String, Assertion> entry : model.get("p").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
            }
        }

        if (model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.get("g").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
            }
        }
    }

    /**
     * savePolicyToText saves the policy to the text.
     *
     * @return the policy text.
     */
    public String savePolicyToText() {
        StringBuilder res = new StringBuilder();

        if (model.containsKey("p")) {
            for (Map.Entry<String, Assertion> entry : model.get("p").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                for (List<String> rule : ast.policy) {
                    res.append(String.format("%s, %s\n", key, String.join(", ", rule)));
                }
            }
        }

        if (model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.get("g").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                for (List<String> rule : ast.policy) {
                    res.append(String.format("%s, %s\n", key, String.join(", ", rule)));
                }
            }
        }

        return res.toString();
    }

    /**
     * clearPolicy clears all current policy.
     */
    public void clearPolicy() {
        if (model.containsKey("p")) {
            for (Assertion ast : model.get("p").values()) {
                ast.policy = new ArrayList<>();
            }
        }

        if (model.containsKey("g")) {
            for (Assertion ast : model.get("g").values()) {
                ast.policy = new ArrayList<>();
            }
        }
    }

    /**
     * getPolicy gets all rules in a policy.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @return the policy rules of section sec and policy type ptype.
     */
    public List<List<String>> getPolicy(String sec, String ptype) {
        return model.get(sec).get(ptype).policy;
    }

    /**
     * getFilteredPolicy gets rules based on field filters from a policy.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered policy rules of section sec and policy type ptype.
     */
    public List<List<String>> getFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> res = new ArrayList<>();

        for (List<String> rule : model.get(sec).get(ptype).policy) {
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
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the policy rule.
     * @return whether the rule exists.
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
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the policy rule.
     * @return succeeds or not.
     */
    public boolean addPolicy(String sec, String ptype, List<String> rule) {
        if (!hasPolicy(sec, ptype, rule)) {
            model.get(sec).get(ptype).policy.add(rule);
            return true;
        }
        return false;
    }

    /**
     * addPolicies adds policy rules to the model.
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
     */
    public boolean addPolicies(String sec, String ptype, List<List<String>> rules) {
        int size = model.get(sec).get(ptype).policy.size();
        for (List<String> rule : rules) {
            if (!hasPolicy(sec, ptype, rule)) {
                model.get(sec).get(ptype).policy.add(rule);
            }
        }
        return size < model.get(sec).get(ptype).policy.size();
    }

    /**
     * removePolicy removes a policy rule from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the policy rule.
     * @return succeeds or not.
     */
    public boolean removePolicy(String sec, String ptype, List<String> rule) {
        for (int i = 0; i < model.get(sec).get(ptype).policy.size(); i ++) {
            List<String> r = model.get(sec).get(ptype).policy.get(i);
            if (Util.arrayEquals(rule, r)) {
                model.get(sec).get(ptype).policy.remove(i);
                return true;
            }
        }

        return false;
    }

    /**
     * removePolicies removes rules from the current policy.
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
     */
    public boolean removePolicies(String sec, String ptype, List<List<String>> rules) {
        int size = model.get(sec).get(ptype).policy.size();
        for (List<String> rule : rules) {
            for (int i = 0; i < model.get(sec).get(ptype).policy.size(); i ++) {
                List<String> r = model.get(sec).get(ptype).policy.get(i);
                if (Util.arrayEquals(rule, r)) {
                    model.get(sec).get(ptype).policy.remove(i);
                }
            }
        }
        return size > model.get(sec).get(ptype).policy.size();
    }

    /**
     * removeFilteredPolicyReturnsEffects removes policy rules based on field filters from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds(effects.size() > 0) or not.
     */
    public List<List<String>> removeFilteredPolicyReturnsEffects(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> tmp = new ArrayList<>();
        List<List<String>> effects = new ArrayList<>();
        int firstIndex = -1;

        for (List<String> rule : model.get(sec).get(ptype).policy) {
            boolean matched = true;
            for (int i = 0; i < fieldValues.length; i ++) {
                String fieldValue = fieldValues[i];
                if (!fieldValue.equals("") && !rule.get(fieldIndex + i).equals(fieldValue)) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                if (firstIndex == -1) {
                    firstIndex = model.get(sec).get(ptype).policy.indexOf(rule);
                }
                effects.add(rule);
            } else {
                tmp.add(rule);
            }
        }

        if (firstIndex != -1) {
            model.get(sec).get(ptype).policy = tmp;
        }

        return effects;
    }

    /**
     * removeFilteredPolicy removes policy rules based on field filters from the model.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        return removeFilteredPolicyReturnsEffects(sec, ptype, fieldIndex, fieldValues).size() > 0;
    }

    /**
     * getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's index.
     * @return the field values specified by fieldIndex.
     */
    public List<String> getValuesForFieldInPolicy(String sec, String ptype, int fieldIndex) {
        List<String> values = new ArrayList<>();

        for (List<String> rule : model.get(sec).get(ptype).policy) {
            values.add(rule.get(fieldIndex));
        }

        Util.arrayRemoveDuplicates(values);

        return values;
    }

    public void buildIncrementalRoleLinks(RoleManager rm, Model.PolicyOperations op, String sec, String ptype, List<List<String>> rules) {
        if (sec.equals("g")) {
            model.get(sec).get(ptype).buildIncrementalRoleLinks(rm, op, rules);
        }
    }

    public boolean hasPolicies(String sec, String ptype, List<List<String>> rules) {
        for (List<String> rule : rules) {
            if (this.hasPolicy(sec, ptype, rule)) {
                return true;
            }
        }
        return false;
    }
}
