// Copyright 2020 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.persist;

import java.util.List;

/**
 * Dispatcher is the interface for jCasbin dispatcher
 * @author canxer314
 */
public interface Dispatcher {
    /**
     * AddPolicies adds policies rule to all instance.
     *
     * @param sec   the section to which the policies belong, e.g., "p" or "g".
     * @param ptype the policy type, such as "p" for permissions or "g" for roles.
     * @param rules the list of policy rules to be added, where each rule is represented as a list of strings.
     */
    void addPolicies(String sec, String ptype, List<List<String>> rules);

    /**
     * RemovePolicies removes policies rule from all instance.
     *
     * @param sec   the section from which to remove policies, e.g., "p" or "g".
     * @param ptype the policy type to remove, such as "p" or "g".
     * @param rules the list of policy rules to be removed, where each rule is represented as a list of strings.
     */
    void removePolicies(String sec, String ptype, List<List<String>> rules);

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from all instance.
     *
     * @param sec         the section from which to remove policies, e.g., "p" or "g".
     * @param ptype       the policy type to filter, such as "p" or "g".
     * @param fieldIndex  the index of the field to filter on.
     * @param fieldValues the values to filter by for the specified field index.
     */
    void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues);

    /**
     * ClearPolicy clears all current policy in all instances
     */
    void clearPolicy();

    /**
     * UpdatePolicy updates policy rule from all instance.
     *
     * @param sec     the section containing the policy, e.g., "p" or "g".
     * @param ptype   the policy type to update, such as "p" or "g".
     * @param oldRule the existing policy rule to be updated, represented as a list of strings.
     * @param newRule the new policy rule that will replace the old one, represented as a list of strings.
     */
    void updatePolicy(String sec, String ptype, List<String> oldRule, List<String> newRule);
}
