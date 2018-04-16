// Copyright 2017 The casbin Authors. All Rights Reserved.
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

/**
 * Adapter is the interface for Casbin adapters.
 */
public interface Adapter {
    /**
     * loadPolicy loads all policy rules from the storage.
     *
     * @param model the model.
     */
    void loadPolicy(Model model);

    /**
     * savePolicy saves all policy rules to the storage.
     *
     * @param model the model.
     */
    void savePolicy(Model model);

    /**
     * addPolicy adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
     */
    void addPolicy(String sec, String ptype, List<String> rule);

    /**
     * removePolicy removes a policy rule from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
     */
    void removePolicy(String sec, String ptype, List<String> rule);

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     */
    void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues);
}
