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

package org.casbin.jcasbin.main;

import org.casbin.jcasbin.effect.DefaultEffector;
import org.casbin.jcasbin.effect.Effector;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

/**
 * CoreEnforcer is the main interface for authorization enforcement and policy management.
 */
public class CoreEnforcer {
    private String modelPath;
    private Model model;
    private Map<String, Method> fm;
    private Effector eft;

    private Adapter adapter;
    private RoleManager rm;

    private boolean enabled;
    private boolean autoSave;
    private boolean autoBuildRoleLinks;

    /**
     * CoreEnforcer initializes an enforcer with a model file and a policy file.
     */
    public CoreEnforcer(String modelPath, String policyFile) {
        this.modelPath = modelPath;

        this.adapter = new FileAdapter(policyFile);

        this.initialize();

        if (!this.modelPath.equals("")) {
            loadModel();
            loadPolicy();
        }
    }

    /**
     * CoreEnforcer initializes an enforcer with a database adapter.
     */
    public CoreEnforcer(String modelPath, Adapter adapter) {
        this.modelPath = modelPath;

        this.adapter = adapter;

        this.initialize();

        if (!this.modelPath.equals("")) {
            loadModel();
            loadPolicy();
        }
    }

    /**
     * CoreEnforcer initializes an enforcer with a model and a database adapter.
     */
    public CoreEnforcer(Model m, Adapter adapter) {
        this.modelPath = "";
        this.adapter = adapter;

        this.model = m;
        this.model.printModel();
        this.fm = FunctionMap.loadFunctionMap();

        this.initialize();

        if (this.adapter != null) {
            loadPolicy();
        }
    }

    private void initialize() {
        this.rm = new DefaultRoleManager(10);
        this.eft = new DefaultEffector();

        this.enabled = true;
        this.autoSave = true;
        this.autoBuildRoleLinks = true;
    }

    /**
     * newModel creates a model.
     */
    private Model newModel() {
        Model model = new Model();

        return model;
    }

    /**
     * newModel creates a model.
     */
    private Model newModel(String text) {
        Model model = new Model();

        model.loadModelFromText(text);

        return model;
    }

    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     */
    public void loadModel() {
        this.model = newModel();
        this.model.loadModel(this.modelPath);
        this.model.printModel();
        this.fm = FunctionMap.loadFunctionMap();
    }

    /**
     * getModel gets the current model.
     */
    public Model getModel() {
        return this.model;
    }

    /**
     * setModel sets the current model.
     */
    public void setModel(Model model) {
        this.model = model;
        this.fm = FunctionMap.loadFunctionMap();
    }

    /**
     * getAdapter gets the current adapter.
     */
    public Adapter getAdapter() {
        return this.adapter;
    }

    /**
     * setAdapter sets the current adapter.
     */
    public void setAdapter(Adapter adapter) {
        this.adapter = adapter;
    }

    /**
     * SetRoleManager sets the current role manager.
     */
    public void setRoleManager(RoleManager rm) {
        this.rm = rm;
    }

    /**
     * setEffector sets the current effector.
     */
    public void setEffector(Effector eft) {
        this.eft = eft;
    }

    /**
     * clearPolicy clears all policy.
     */
    public void clearPolicy() {
        this.model.clearPolicy();
    }

    /**
     * loadPolicy reloads the policy from file/database.
     */
    public void loadPolicy() {
        this.model.clearPolicy();
        this.adapter.loadPolicy(this.model);

        this.model.printPolicy();
        if (this.autoBuildRoleLinks) {
            this.buildRoleLinks();
        }
    }

    /**
     * savePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
     */
    public void savePolicy() {
        this.adapter.savePolicy(this.model);
    }

    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
     */
    public void enableEnforce(boolean enable) {
        this.enabled = enable;
    }

    /**
     * enableLog changes whether to print Casbin log to the standard output.
     */
    public void enableLog(boolean enable) {
        Util.enableLog = enable;
    }

    /**
     * enableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
     */
    public void enableAutoSave(boolean autoSave) {
        this.autoSave = autoSave;
    }

    /**
     * enableAutoBuildRoleLinks controls whether to save a policy rule automatically to the adapter when it is added or removed.
     */
    public void enableAutoBuildRoleLinks(boolean autoBuildRoleLinks) {
        this.autoBuildRoleLinks = autoBuildRoleLinks;
    }

    /**
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
     */
    public void buildRoleLinks() {
        this.rm.clear();
        this.model.buildRoleLinks(this.rm);
    }

    /**
     * enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
     */
    public boolean enforce(String... rvals) {
        return true;
    }

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
     * addPolicy adds a rule to the current policy.
     */
    private boolean addPolicy(String sec, String ptype, List<String> rule) {
        boolean ruleAdded = this.model.addPolicy(sec, ptype, rule);

        if (ruleAdded) {
            if (this.adapter != null && this.autoSave) {
                this.adapter.addPolicy(sec, ptype, rule);
            }
        }

        return ruleAdded;
    }

    /**
     * removePolicy removes a rule from the current policy.
     */
    private boolean removePolicy(String sec, String ptype, List<String> rule) {
        boolean ruleRemoved = this.model.removePolicy(sec, ptype, rule);

        if (ruleRemoved) {
            if (this.adapter != null && this.autoSave) {
                this.adapter.removePolicy(sec, ptype, rule);
            }
        }

        return ruleRemoved;
    }

    /**
     * removeFilteredPolicy removes rules based on field filters from the current policy.
     */
    private boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        boolean ruleRemoved = this.model.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);

        if (ruleRemoved) {
            if (this.adapter != null && this.autoSave) {
                this.adapter.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
            }
        }

        return ruleRemoved;
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
