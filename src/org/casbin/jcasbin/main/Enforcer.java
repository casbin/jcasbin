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
import org.casbin.jcasbin.rbac.RoleManagerConstructor;

import java.lang.reflect.Method;
import java.util.Map;

/**
 * Enforcer is the main interface for authorization enforcement and policy management.
 */
public class Enforcer {
    String modelPath;
    Model model;
    Map<String, Method> fm;
    RoleManagerConstructor rmc;

    Adapter adapter;

    boolean enabled;
    boolean autoSave;

    /**
     * Enforcer initializes an enforcer with a model file and a policy file.
     */
    public Enforcer(String modelPath, String policyFile) {
        this.modelPath = modelPath;

        this.adapter = new FileAdapter(policyFile);

        this.enabled = true;
        this.autoSave = true;

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

        this.enabled = true;
        this.autoSave = true;

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

        this.enabled = true;
        this.autoSave = true;

        if (this.adapter != null) {
            loadPolicy();
        }
    }

    /**
     * newModel creates a model.
     */
    public Model newModel(String... text) {
        return null;
    }

    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     */
    public void loadModel() {
    }

    /**
     * getModel gets the current model.
     */
    public Model getModel() {
        return null;
    }

    /**
     * setModel sets the current model.
     */
    public void setModel(Model model) {
    }

    /**
     * getAdapter gets the current adapter.
     */
    public Adapter getAdapter() {
        return null;
    }

    /**
     * setAdapter sets the current adapter.
     */
    public void setAdapter(Adapter adapter) {
    }

    /**
     * setRoleManager sets the constructor function for creating a RoleManager.
     */
    public void setRoleManager(RoleManagerConstructor rmc) {
    }

    /**
     * clearPolicy clears all policy.
     */
    public void clearPolicy() {
    }

    /**
     * loadPolicy reloads the policy from file/database.
     */
    public void loadPolicy() {
    }

    /**
     * savePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
     */
    public void savePolicy() {
    }

    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
     */
    public void enableEnforce(boolean enable) {
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
    }

    /**
     * enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
     */
    public boolean enforce(String... rvals) {
        return true;
    }
}
