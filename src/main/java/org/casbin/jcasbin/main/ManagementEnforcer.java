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

package org.casbin.jcasbin.main;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

public class ManagementEnforcer extends InternalEnforcer {
    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     */
    public List<String> getAllSubjects() {
        return getAllNamedSubjects("p");
    }

    /**
     * GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
     */
    public List<String> getAllNamedSubjects(String ptype) {
        return model.getValuesForFieldInPolicy("p", ptype, 0);
    }

    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     */
    public List<String> getAllObjects() {
        return getAllNamedObjects("p");
    }

    /**
     * getAllNamedObjects gets the list of objects that show up in the current named policy.
     */
    public List<String> getAllNamedObjects(String ptype) {
        return model.getValuesForFieldInPolicy("p", ptype, 1);
    }

    /**
     * getAllActions gets the list of actions that show up in the current policy.
     */
    public List<String> getAllActions() {
        return getAllNamedActions("p");
    }

    /**
     * GetAllNamedActions gets the list of actions that show up in the current named policy.
     */
    public List<String> getAllNamedActions(String ptype) {
        return model.getValuesForFieldInPolicy("p", ptype, 2);
    }

    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     */
    public List<String> getAllRoles() {
        return getAllNamedRoles("g");
    }

    /**
     * getAllNamedRoles gets the list of roles that show up in the current named policy.
     */
    public List<String> getAllNamedRoles(String ptype) {
        return model.getValuesForFieldInPolicy("g", ptype, 1);
    }

    /**
     * getPolicy gets all the authorization rules in the policy.
     */
    public List<List<String>> getPolicy() {
        return getNamedPolicy("p");
    }

    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredPolicy(int fieldIndex, String... fieldValues) {
        return getFilteredNamedPolicy("p", fieldIndex, fieldValues);
    }

    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     */
    public List<List<String>> getNamedPolicy(String ptype) {
        return model.getPolicy("p", ptype);
    }

    /**
     * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
     */
    public List<List<String>> getFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return model.getFilteredPolicy("p", ptype, fieldIndex, fieldValues);
    }

    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     */
    public List<List<String>> getGroupingPolicy() {
        return getNamedGroupingPolicy("g");
    }

    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return getFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
    }

    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     */
    public List<List<String>> getNamedGroupingPolicy(String ptype) {
        return model.getPolicy("g", ptype);
    }

    /**
     * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return model.getFilteredPolicy("g", ptype, fieldIndex, fieldValues);
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     */
    public boolean hasPolicy(List<String> params) {
        return hasNamedPolicy("p", params);
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     */
    public boolean hasPolicy(String... params) {
        return hasPolicy(Arrays.asList(params));
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     */
    public boolean hasNamedPolicy(String ptype, List<String> params) {
        return model.hasPolicy("p", ptype, params);
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     */
    public boolean hasNamedPolicy(String ptype, String... params) {
        return hasNamedPolicy(ptype, Arrays.asList(params));
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addPolicy(List<String> params) {
        return addNamedPolicy("p", params);
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addPolicy(String... params) {
        return addPolicy(Arrays.asList(params));
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addNamedPolicy(String ptype, List<String> params) {
        return addPolicy("p", ptype, params);
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addNamedPolicy(String ptype, String... params) {
        return addNamedPolicy(ptype, Arrays.asList(params));
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     */
    public boolean removePolicy(List<String> params) {
        return removeNamedPolicy("p", params);
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     */
    public boolean removePolicy(String... params) {
        return removePolicy(Arrays.asList(params));
    }

    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     */
    public boolean removeFilteredPolicy(int fieldIndex, String... fieldValues) {
        return removeFilteredNamedPolicy("p", fieldIndex, fieldValues);
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     */
    public boolean removeNamedPolicy(String ptype, List<String> params) {
        return removePolicy("p", ptype, params);
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     */
    public boolean removeNamedPolicy(String ptype, String... params) {
        return removeNamedPolicy(ptype, Arrays.asList(params));
    }

    /**
     * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
     */
    public boolean removeFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return removeFilteredPolicy("p", ptype, fieldIndex, fieldValues);
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     */
    public boolean hasGroupingPolicy(List<String> params) {
        return hasNamedGroupingPolicy("g", params);
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     */
    public boolean hasGroupingPolicy(String... params) {
        return hasGroupingPolicy(Arrays.asList(params));
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     */
    public boolean hasNamedGroupingPolicy(String ptype, List<String> params) {
        return model.hasPolicy("g", ptype, params);
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     */
    public boolean hasNamedGroupingPolicy(String ptype, String... params) {
        return hasNamedGroupingPolicy(ptype, Arrays.asList(params));
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addGroupingPolicy(List<String> params) {
        return addNamedGroupingPolicy("g", params);
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addGroupingPolicy(String... params) {
        return addGroupingPolicy(Arrays.asList(params));
    }

    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addNamedGroupingPolicy(String ptype, List<String> params) {
        boolean ruleAdded = addPolicy("g", ptype, params);

        if (autoBuildRoleLinks) {
            buildRoleLinks();
        }
        return ruleAdded;
    }

    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addNamedGroupingPolicy(String ptype, String... params) {
        return addNamedGroupingPolicy(ptype, Arrays.asList(params));
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     */
    public boolean removeGroupingPolicy(List<String> params) {
        return removeNamedGroupingPolicy("g", params);
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     */
    public boolean removeGroupingPolicy(String... params) {
        return removeGroupingPolicy(Arrays.asList(params));
    }

    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     */
    public boolean removeFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return removeFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     */
    public boolean removeNamedGroupingPolicy(String ptype, List<String> params) {
        boolean ruleRemoved = removePolicy("g", ptype, params);

        if (autoBuildRoleLinks) {
            buildRoleLinks();
        }
        return ruleRemoved;
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     */
    public boolean removeNamedGroupingPolicy(String ptype, String... params) {
        return removeNamedGroupingPolicy(ptype, Arrays.asList(params));
    }

    /**
     * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
     */
    public boolean removeFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        boolean ruleRemoved = removeFilteredPolicy("g", ptype, fieldIndex, fieldValues);

        if (autoBuildRoleLinks) {
            buildRoleLinks();
        }
        return ruleRemoved;
    }

    /**
     * addFunction adds a customized function.
     */
    public void addFunction(String ptype, Method function) {
    }
}
