// Copyright 2018 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Enforcer extends ManagementEnforcer {
    /**
     * CoreEnforcer is the default constructor.
     */
    public Enforcer() {
        this("", "");
    }

    /**
     * CoreEnforcer initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath the path of the model file.
     * @param policyFile the path of the policy file.
     */
    public Enforcer(String modelPath, String policyFile) {
        this(modelPath, new FileAdapter(policyFile));
    }

    /**
     * CoreEnforcer initializes an enforcer with a database adapter.
     *
     * @param modelPath the path of the model file.
     * @param adapter the adapter.
     */
    public Enforcer(String modelPath, Adapter adapter) {
        this(newModel(modelPath, ""), adapter);

        this.modelPath = modelPath;
    }

    /**
     * CoreEnforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m the model.
     * @param adapter the adapter.
     */
    public Enforcer(Model m, Adapter adapter) {
        this.adapter = adapter;
        this.watcher = null;

        model = m;
        model.printModel();
        fm = FunctionMap.loadFunctionMap();

        initialize();

        if (this.adapter != null) {
            loadPolicy();
        }
    }

    /**
     * CoreEnforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    public Enforcer(Model m) {
        this(m, null);
    }

    /**
     * CoreEnforcer initializes an enforcer with a model file.
     *
     * @param modelPath the path of the model file.
     */
    public Enforcer(String modelPath) {
        this(modelPath, "");
    }

    /**
     * CoreEnforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param modelPath the path of the model file.
     * @param policyFile the path of the policy file.
     * @param enableLog whether to enable Casbin's log.
     */
    public Enforcer(String modelPath, String policyFile, boolean enableLog) {
        this(modelPath, new FileAdapter(policyFile));
        this.enableLog(enableLog);
    }

    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @return the roles that the user has.
     */
    public List<String> getRolesForUser(String name) {
        return model.model.get("g").get("g").rm.getRoles(name);
    }

    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @return the users that has the role.
     */
    public List<String> getUsersForRole(String name) {
        return model.model.get("g").get("g").rm.getUsers(name);
    }

    /**
     * hasRoleForUser determines whether a user has a role.
     *
     * @param name the user.
     * @param role the role.
     * @return whether the user has the role.
     */
    public boolean hasRoleForUser(String name, String role) {
        List<String> roles = getRolesForUser(name);

        boolean hasRole = false;
        for (String r : roles) {
            if (r.equals(role)) {
                hasRole = true;
                break;
            }
        }

        return hasRole;
    }

    /**
     * addRoleForUser adds a role for a user.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    public boolean addRoleForUser(String user, String role) {
        return addGroupingPolicy(user, role);
    }

    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    public boolean deleteRoleForUser(String user, String role) {
        return removeGroupingPolicy(user, role);
    }

    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    public boolean deleteRolesForUser(String user) {
        return removeFilteredGroupingPolicy(0, user);
    }

    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    public boolean deleteUser(String user) {
        return removeFilteredGroupingPolicy(0, user);
    }

    /**
     * deleteRole deletes a role.
     *
     * @param role the role.
     */
    public void deleteRole(String role) {
        removeFilteredGroupingPolicy(1, role);
        removeFilteredPolicy(0, role);
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean deletePermission(String... permission) {
        return removeFilteredPolicy(1, permission);
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean addPermissionForUser(String user, String... permission) {
        List<String> params = new ArrayList<>();

        params.add(user);
        Collections.addAll(params, permission);

        return addPolicy(params);
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean deletePermissionForUser(String user, String... permission) {
        List<String> params = new ArrayList<>();

        params.add(user);
        Collections.addAll(params, permission);

        return removePolicy(params);
    }

    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    public boolean deletePermissionsForUser(String user) {
        return removeFilteredPolicy(0, user);
    }

    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user the user.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    public List<List<String>> getPermissionsForUser(String user) {
        return getFilteredPolicy(0, user);
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    public boolean hasPermissionForUser(String user, String... permission) {
        List<String> params = new ArrayList<>();

        params.add(user);
        Collections.addAll(params, permission);

        return hasPolicy(params);
    }
}
