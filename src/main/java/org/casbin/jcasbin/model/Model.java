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

import org.casbin.jcasbin.config.Config;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model represents the whole access control model.
 */
public class Model {
    Map<String, Map<String, Assertion>> model;

    static Map<String, String> sectionNameMap;

    static {
        sectionNameMap = new HashMap<>();
        sectionNameMap.put("r", "request_definition");
        sectionNameMap.put("p", "policy_definition");
        sectionNameMap.put("g", "role_definition");
        sectionNameMap.put("e", "policy_effect");
        sectionNameMap.put("m", "matchers");
    }

    private boolean loadAssertion(Model model, Config cfg, String sec, String key) {
        String value = cfg.getString(sectionNameMap.get(sec) + "::" + key);
        return model.addDef(sec, key, value);
    }

    /**
     * addDef adds an assertion to the model.
     */
    public boolean addDef(String sec, String key, String value) {
        Assertion ast = new Assertion();
        ast.key = key;
        ast.value = value;

        if (ast.value.equals("")) {
            return false;
        }

        if (sec.equals("r") || sec.equals("p")) {
            ast.tokens = ast.value.split(", ");
            for (int i = 0; i < ast.tokens.length; i ++) {
                ast.tokens[i] = key + "_" + ast.tokens[i];
            }
        } else {
            ast.value = Util.removeComments(Util.escapeAssertion(ast.value));
        }

        if (!model.containsKey(sec)) {
            model.put(sec, new HashMap<String, Assertion>());
        }

        model.get(sec).put(key, ast);
        return true;
    }

    private String getKeySuffix(int i) {
        if (i == 1) {
            return "";
        }

        return Integer.toString(i);
    }

    private void loadSection(Model model, Config cfg, String sec) {
        int i = 1;
        while (true) {
            if (!loadAssertion(model, cfg, sec, sec + getKeySuffix(i))) {
                break;
            } else {
                i ++;
            }
        }
    }

    /**
     * loadModel loads the model from model CONF file.
     */
    public void loadModel(String path) {
        Config cfg = Config.newConfig(path);

        loadSection(this, cfg, "r");
        loadSection(this, cfg, "p");
        loadSection(this, cfg, "e");
        loadSection(this, cfg, "m");

        loadSection(this, cfg, "g");
    }

    /**
     * loadModelFromText loads the model from the text.
     */
    public void loadModelFromText(String text) {
        Config cfg = Config.newConfigFromText(text);

        loadSection(this, cfg, "r");
        loadSection(this, cfg, "p");
        loadSection(this, cfg, "e");
        loadSection(this, cfg, "m");

        loadSection(this, cfg, "g");
    }

    /**
     * printModel prints the model to the log.
     */
    public void printModel() {
        Util.logPrint("Model:");
        for (Map.Entry<String, Map<String, Assertion>> entry : this.model.entrySet()) {
            for (Map.Entry<String, Assertion> entry2 : entry.getValue().entrySet()) {
                Util.logPrintf("%s.%s: %s", entry.getKey(), entry2.getKey(), entry2.getValue().value);
            }
        }
    }

    /**
     * buildRoleLinks initializes the roles in RBAC.
     */
    public void buildRoleLinks(RoleManager rm) {
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
