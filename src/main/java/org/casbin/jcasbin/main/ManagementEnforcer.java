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
import java.util.List;

public class ManagementEnforcer extends InternalEnforcer {
    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     */
    public List<String> getAllSubjects() {
        return this.getAllNamedSubjects("p");
    }

    /**
     * GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
     */
    public List<String> getAllNamedSubjects(String ptype) {
        return this.model.getValuesForFieldInPolicy("p", ptype, 0);
    }

    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     */
    public List<String> getAllObjects() {
        return this.getAllNamedObjects("p");
    }

    /**
     * getAllNamedObjects gets the list of objects that show up in the current named policy.
     */
    public List<String> getAllNamedObjects(String ptype) {
        return this.model.getValuesForFieldInPolicy("p", ptype, 1);
    }

    /**
     * getAllActions gets the list of actions that show up in the current policy.
     */
    public List<String> getAllActions() {
        return this.getAllNamedActions("p");
    }

    /**
     * GetAllNamedActions gets the list of actions that show up in the current named policy.
     */
    public List<String> getAllNamedActions(String ptype) {
        return this.model.getValuesForFieldInPolicy("p", ptype, 2);
    }

    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     */
    public List<String> getAllRoles() {
        return this.getAllNamedRoles("g");
    }

    /**
     * getAllNamedRoles gets the list of roles that show up in the current named policy.
     */
    public List<String> getAllNamedRoles(String ptype) {
        return this.model.getValuesForFieldInPolicy("g", ptype, 1);
    }

    /**
     * getPolicy gets all the authorization rules in the policy.
     */
    public List<List<String>> getPolicy() {
        return this.getNamedPolicy("p");
    }

    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredPolicy(int fieldIndex, String... fieldValues) {
        return this.getFilteredNamedPolicy("p", fieldIndex, fieldValues);
    }

    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     */
    public List<List<String>> getNamedPolicy(String ptype) {
        return this.model.getPolicy("p", ptype);
    }

    /**
     * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
     */
    public List<List<String>> getFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return this.model.getFilteredPolicy("p", ptype, fieldIndex, fieldValues);
    }

    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     */
    public List<List<String>> getGroupingPolicy() {
        return this.getNamedGroupingPolicy("g");
    }

    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return this.getFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
    }

    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     */
    public List<List<String>> getNamedGroupingPolicy(String ptype) {
        return this.model.getPolicy("g", ptype);
    }

    /**
     * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return this.model.getFilteredPolicy("g", ptype, fieldIndex, fieldValues);
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     */
    public boolean hasPolicy(List<String> params) {
        return this.hasNamedPolicy("p", params);
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     */
    public boolean hasNamedPolicy(String ptype, List<String> params) {
        return this.model.hasPolicy("p", ptype, params);
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addPolicy(List<String> params) {
        return this.addNamedPolicy("p", params);
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addNamedPolicy(String ptype, List<String> params) {
        return this.addPolicy("p", ptype, params);
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     */
    public boolean removePolicy(List<String> params) {
        return this.removeNamedPolicy("p", params);
    }

    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     */
    public boolean removeFilteredPolicy(int fieldIndex, String... fieldValues) {
        return this.removeFilteredNamedPolicy("p", fieldIndex, fieldValues);
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     */
    public boolean removeNamedPolicy(String ptype, List<String> params) {
        return this.removePolicy("p", ptype, params);
    }

    /**
     * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
     */
    public boolean removeFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return this.removeFilteredPolicy("p", ptype, fieldIndex, fieldValues);
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     */
    public boolean hasGroupingPolicy(List<String> params) {
        return this.hasNamedGroupingPolicy("g", params);
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     */
    public boolean hasNamedGroupingPolicy(String ptype, List<String> params) {
        return this.model.hasPolicy("g", ptype, params);
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addGroupingPolicy(List<String> params) {
        return this.addNamedGroupingPolicy("g", params);
    }

    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addNamedGroupingPolicy(String ptype, List<String> params) {
        boolean ruleAdded = this.addPolicy("g", ptype, params);

        if (this.autoBuildRoleLinks) {
            this.buildRoleLinks();
        }
        return ruleAdded;
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     */
    public boolean removeGroupingPolicy(List<String> params) {
        return this.removeNamedGroupingPolicy("g", params);
    }

    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     */
    public boolean removeFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return this.removeFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     */
    public boolean removeNamedGroupingPolicy(String ptype, List<String> params) {
        boolean ruleRemoved = this.removePolicy("g", ptype, params);

        if (this.autoBuildRoleLinks) {
            this.buildRoleLinks();
        }
        return ruleRemoved;
    }

    /**
     * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
     */
    public boolean removeFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        boolean ruleRemoved = this.removeFilteredPolicy("g", ptype, fieldIndex, fieldValues);

        if (this.autoBuildRoleLinks) {
            this.buildRoleLinks();
        }
        return ruleRemoved;
    }

    /**
     * addFunction adds a customized function.
     */
    public void addFunction(String ptype, Method function) {
    }
}
