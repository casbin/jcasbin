// Copyright 2021 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.model.Model;

import java.util.List;

/**
 * StringAdapter is the string adapter for Casbin.
 * It can load policy from string.
 */
public class StringAdapter implements Adapter {
    private String policy;

    /**
     * StringAdapter is the constructor for StringAdapter.
     *
     * @param policy the policy string.
     */
    public StringAdapter(String policy) {
        this.policy = policy;
    }

    /**
     * loadPolicy loads all policy rules from the storage.
     */
    @Override
    public void loadPolicy(Model model) {
        if (policy == null) {
            throw new CasbinAdapterException("Policy is null");
        }
        loadPolicyData(model, Helper::loadPolicyLine);
    }

    private void loadPolicyData(Model model, Helper.loadPolicyLineHandler<String, Model> handler) {
        String[] lines = policy.split(System.lineSeparator());
        for (String line : lines) {
            handler.accept(line, model);
        }
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    @Override
    public void savePolicy(Model model) {
        throw new UnsupportedOperationException("not implemented");

    }

    /**
     * addPolicy adds a policy rule to the storage.
     */
    @Override
    public void addPolicy(String sec, String ptype, List<String> rule) {
        throw new UnsupportedOperationException("not implemented");

    }

    /**
     * removePolicy removes a policy rule from the storage.
     */
    @Override
    public void removePolicy(String sec, String ptype, List<String> rule) {
        throw new UnsupportedOperationException("not implemented");

    }

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the
     * storage.
     */
    @Override
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        throw new UnsupportedOperationException("not implemented");

    }
}
