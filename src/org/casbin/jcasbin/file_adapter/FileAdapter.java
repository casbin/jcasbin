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

package org.casbin.jcasbin.file_adapter;

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;

import java.lang.reflect.Method;
import java.util.List;

/**
 * FileAdapter is the file adapter for Casbin.
 * It can load policy from file or save policy to file.
 */
public class FileAdapter implements Adapter {
    private String filePath;

    /**
     * FileAdapter is the constructor for FileAdapter.
     */
    public FileAdapter(String filePath) {
        this.filePath = filePath;
    }

    /**
     * loadPolicy loads all policy rules from the storage.
     */
    public void loadPolicy(Model model) {
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    public void savePolicy(Model model) {
    }


    private void loadPolicyFile(Model model, Method handler) {
    }

    private void savePolicyFile(String text) {
    }

    /**
     * addPolicy adds a policy rule to the storage.
     */
    public void addPolicy(String sec, String ptype, List<String> rule) {
    }

    /**
     * removePolicy removes a policy rule from the storage.
     */
    public void removePolicy(String sec, String ptype, List<String> rule) {
    }

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     */
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
    }
}
