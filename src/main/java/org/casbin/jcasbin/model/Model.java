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

import static org.casbin.jcasbin.util.Util.splitCommaDelimited;

import org.casbin.jcasbin.config.Config;
import org.casbin.jcasbin.util.Util;

import java.util.HashMap;
import java.util.Map;

/**
 * Model represents the whole access control model.
 */
public class Model extends Policy {
    private static final Map<String, String> sectionNameMap;

    static {
        sectionNameMap = new HashMap<>();
        sectionNameMap.put("r", "request_definition");
        sectionNameMap.put("p", "policy_definition");
        sectionNameMap.put("g", "role_definition");
        sectionNameMap.put("e", "policy_effect");
        sectionNameMap.put("m", "matchers");
    }

    // used by CoreEnforcer to detect changes to Model
    protected int modCount;

    public Model() {
        model = new HashMap<>();
    }

    public int getModCount() {
        return modCount;
    }

    private boolean loadAssertion(Model model, Config cfg, String sec, String key) {
        String value = cfg.getString(sectionNameMap.get(sec) + "::" + key);
        return model.addDef(sec, key, value);
    }

    /**
     * addDef adds an assertion to the model.
     *
     * @param sec the section, "p" or "g".
     * @param key the policy type, "p", "p2", .. or "g", "g2", ..
     * @param value the policy rule, separated by ", ".
     * @return succeeds or not.
     */
    public boolean addDef(String sec, String key, String value) {
        Assertion ast = new Assertion();
        ast.key = key;
        ast.value = value;

        if (ast.value.equals("")) {
            return false;
        }

        if (sec.equals("r") || sec.equals("p")) {
            ast.tokens = splitCommaDelimited(ast.value);
            for (int i = 0; i < ast.tokens.length; i ++) {
                ast.tokens[i] = key + "_" + ast.tokens[i];
            }
        } else {
            ast.value = Util.removeComments(Util.escapeAssertion(ast.value));
        }

        if (!model.containsKey(sec)) {
            model.put(sec, new HashMap<>());
        }

        model.get(sec).put(key, ast);
        modCount++;
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
     *
     * @param path the path of the model file.
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
     *
     * @param text the model text.
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
     * saveSectionToText saves the section to the text.
     *
     * @return the section text.
     */
    private String saveSectionToText(String sec) {
        StringBuilder res = new StringBuilder("[" + sectionNameMap.get(sec) + "]\n");

        Map<String, Assertion> section = model.get(sec);
        if (section == null) {
            return "";
        }

        for (Map.Entry<String, Assertion> entry : section.entrySet()) {
            res.append(String.format("%s = %s\n", entry.getKey(), entry.getValue().value.replace("_", ".")));
        }

        return res.toString();
    }

    /**
     * saveModelToText saves the model to the text.
     *
     * @return the model text.
     */
    public String saveModelToText() {
        StringBuilder res = new StringBuilder();

        res.append(saveSectionToText("r"));
        res.append("\n");
        res.append(saveSectionToText("p"));
        res.append("\n");

        String g = saveSectionToText("g");
        g = g.replace(".", "_");
        res.append(g);
        if (!g.equals("")) {
            res.append("\n");
        }

        res.append(saveSectionToText("e"));
        res.append("\n");
        res.append(saveSectionToText("m"));

        return res.toString();
    }

    /**
     * printModel prints the model to the log.
     */
    public void printModel() {
        Util.logPrint("Model:");
        for (Map.Entry<String, Map<String, Assertion>> entry : model.entrySet()) {
            for (Map.Entry<String, Assertion> entry2 : entry.getValue().entrySet()) {
                Util.logPrintf("%s.%s: %s", entry.getKey(), entry2.getKey(), entry2.getValue().value);
            }
        }
    }

    public enum PolicyOperations {
        POLICY_ADD,
        POLICY_REMOVE
    }
}
