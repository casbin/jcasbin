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

import org.casbin.jcasbin.file_adapter.FileAdapter;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

/**
 * Enforcer is the main interface for authorization enforcement and policy management.
 */
public class Enforcer {
    String modelPath;
    Model model;
    Map<String, Method> fm;

    Adapter adapter;
    RoleManager rm;

    boolean enabled;
    boolean autoSave;
    boolean autoBuildRoleLinks;

    /**
     * Enforcer initializes an enforcer with a model file and a policy file.
     */
    public Enforcer(String modelPath, String policyFile) {
        this.modelPath = modelPath;

        this.adapter = new FileAdapter(policyFile);

        this.initialize();

        if (!this.modelPath.equals("")) {
            loadModel();
            loadPolicy();
        }
    }

    /**
     * Enforcer initializes an enforcer with a database adapter.
     */
    public Enforcer(String modelPath, Adapter adapter) {
        this.modelPath = modelPath;

        this.adapter = adapter;

        this.initialize();

        if (!this.modelPath.equals("")) {
            loadModel();
            loadPolicy();
        }
    }

    /**
     * Enforcer initializes an enforcer with a model and a database adapter.
     */
    public Enforcer(Model m, Adapter adapter) {
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
    }

    /**
     * enableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
     */
    public void enableAutoSave(boolean autoSave) {
        this.autoSave = autoSave;
    }

    /**
     * buildRoleLinks manually rebuild the role inheritance relations.
     */
    public void buildRoleLinks() {
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
        return null;
    }

    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     */
    public List<String> getAllObjects() {
        return null;
    }

    /**
     * getAllActions gets the list of actions that show up in the current policy.
     */
    public List<String> getAllActions() {
        return null;
    }

    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     */
    public List<String> getAllRoles() {
        return null;
    }

    /**
     * getPolicy gets all the authorization rules in the policy.
     */
    public List<List<String>> getPolicy() {
        return null;
    }

    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredPolicy() {
        return null;
    }

    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     */
    public List<List<String>> getGroupingPolicy() {
        return null;
    }

    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     */
    public List<List<String>> getFilteredGroupingPolicy() {
        return null;
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     */
    public boolean hasPolicy(List<String> policy) {
        return true;
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addPolicy(List<String> policy) {
        return true;
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     */
    public boolean removePolicy(List<String> policy) {
        return true;
    }

    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     */
    public boolean removeFilteredPolicy(int fieldIndex, String fieldValues) {
        return true;
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     */
    public boolean hasGroupingPolicy(List<String> policy) {
        return true;
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     */
    public boolean addGroupingPolicy(List<String> policy) {
        return true;
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     */
    public boolean removeGroupingPolicy(List<String> policy) {
        return true;
    }

    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     */
    public boolean removeFilteredGroupingPolicy(int fieldIndex, String fieldValues) {
        return true;
    }

    /**
     * addFunction adds a customized function.
     */
    public void addFunction(String name, Method function) {
    }
}
