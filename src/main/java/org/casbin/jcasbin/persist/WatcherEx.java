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

import org.casbin.jcasbin.model.Model;

import java.util.List;

public interface WatcherEx extends Watcher {
    /**
     * updateForAddPolicy calls the update callback of other instances to synchronize their policy.
     * It is called after a policy is added via Enforcer.addPolicy(), Enforcer.addNamedPolicy(),
     * Enforcer.addGroupingPolicy() and Enforcer.addNamedGroupingPolicy().
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param params      the policy
     */
     void updateForAddPolicy(String sec, String ptype, String... params);

    /**
     * updateForRemovePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after a policy is removed by Enforcer.removePolicy(), Enforcer.removeNamedPolicy(),
     * Enforcer.removeGroupingPolicy() and Enforcer.removeNamedGroupingPolicy().
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param params      the policy
     */
    void updateForRemovePolicy(String sec, String ptype, String... params);

    /**
     * updateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
     * It is called after Enforcer.RemoveFilteredPolicy(), Enforcer.RemoveFilteredNamedPolicy(),
     * Enforcer.RemoveFilteredGroupingPolicy() and Enforcer.RemoveFilteredNamedGroupingPolicy().
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex  the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value "" means not to match this field.
     */
    void updateForRemoveFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues);

    /**
     * updateForSavePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after Enforcer.savePolicy()
     *
     * @param model       represents the whole access control model.
     */
    void updateForSavePolicy(Model model);

    /**
     * updateForAddPolicies calls the update callback of other instances to synchronize their policy.
     * It is called after Enforcer.addPolicies(), Enforcer.addNamedPolicies(),
     * Enforcer.addGroupingPolicies() and Enforcer.addNamedGroupingPolicies().
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules       the policies
     */
    void updateForAddPolicies(String sec, String ptype, List<List<String>> rules);

    /**
     * updateForRemovePolicies calls the update callback of other instances to synchronize their policy.
     * It is called after Enforcer.removePolicies(), Enforcer.removeNamedPolicies(),
     * Enforcer.removeGroupingPolicies() and Enforcer.removeNamedGroupingPolicies().
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules       the policies
     */
    void updateForRemovePolicies(String sec, String ptype, List<List<String>> rules);

    /**
     *
     */
    enum UpdateType {
        Update,
        UpdateForAddPolicies,
        UpdateForAddPolicy,
        UpdateForRemoveFilteredPolicy,
        UpdateForRemovePolicies,
        UpdateForRemovePolicy,
        UpdateForSavePolicy,
        UpdateForUpdatePolicies,
        UpdateForUpdatePolicy

    }

}
