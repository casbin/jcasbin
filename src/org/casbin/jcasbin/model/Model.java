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

package org.casbin.jcasbin.model;

import org.casbin.jcasbin.config.ConfigInterface;

import java.util.List;
import java.util.Map;

/**
 * Model represents the whole access control model.
 */
public class Model {
    Map<String, Map<String, Assertion>> Model;
    Map<String, String> sectionNameMap;

    private boolean loadAssertion(ConfigInterface cfg, String sec, String key) {
        return true;
    }

    /**
     * addDef adds an assertion to the model.
     */
    public boolean addDef(String sec, String key, String value) {
        return true;
    }

    private String getKeySuffix(int i) {
        return "";
    }

    private void loadSection(ConfigInterface cfg, String sec) {
    }

    /**
     * loadModel loads the model from model CONF file.
     */
    public void loadModel(String path) {
    }

    /**
     * loadModelFromText loads the model from the text.
     */
    public void loadModelFromText(String text) {
    }

    /**
     * printModel prints the model to the log.
     */
    public void printModel() {
    }

    /**
     * buildRoleLinks initializes the roles in RBAC.
     */
    public void buildRoleLinks() {
    }

    /**
     * printPolicy prints the policy to log.
     */
    public void printPolicy() {
    }

    /**
     * clearPolicy clears all current policy.
     */
    public void clearPolicy() {
    }

    /**
     * getPolicy gets all rules in a policy.
     */
    public List<List<String>> getPolicy(String sec, String ptype) {
        return null;
    }

    /**
     * getFilteredPolicy gets rules based on field filters from a policy.
     */
    public List<List<String>> getFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        return null;
    }

    /**
     * hasPolicy determines whether a model has the specified policy rule.
     */
    public boolean hasPolicy(String sec, String ptype, List<String> rule) {
        return true;
    }

    /**
     * addPolicy adds a policy rule to the model.
     */
    public boolean addPolicy(String sec, String ptype, List<String> rule) {
        return true;
    }

    /**
     * removePolicy removes a policy rule from the model.
     */
    public boolean removePolicy(String sec, String ptype, List<String> rule) {
        return true;
    }

    /**
     * removeFilteredPolicy removes policy rules based on field filters from the model.
     */
    public boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        return true;
    }

    /**
     * getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
     */
    public List<String> getValuesForFieldInPolicy(String sec, String ptype, int fieldIndex) {
        return null;
    }
}
