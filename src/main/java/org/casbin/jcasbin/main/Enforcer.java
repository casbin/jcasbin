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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Enforcer extends ManagementEnforcer {
    /**
     * getRolesForUser gets the roles that a user has.
     */
    public List<String> getRolesForUser(String name) {
        return model.model.get("g").get("g").rm.getRoles(name);
    }

    /**
     * getUsersForRole gets the users that has a role.
     */
    public List<String> getUsersForRole(String name) {
        return model.model.get("g").get("g").rm.getUsers(name);
    }

    /**
     * hasRoleForUser determines whether a user has a role.
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
     */
    public boolean addRoleForUser(String user, String role) {
        return addGroupingPolicy(user, role);
    }

    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     */
    public boolean deleteRoleForUser(String user, String role) {
        return removeGroupingPolicy(user, role);
    }

    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     */
    public boolean deleteRolesForUser(String user) {
        return removeFilteredGroupingPolicy(0, user);
    }

    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     */
    public boolean deleteUser(String user) {
        return removeFilteredGroupingPolicy(0, user);
    }

    /**
     * deleteRole deletes a role.
     */
    public void deleteRole(String role) {
        removeFilteredGroupingPolicy(1, role);
        removeFilteredPolicy(0, role);
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     */
    public boolean deletePermission(String... permission) {
        return removeFilteredPolicy(1, permission);
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
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
     */
    public boolean deletePermissionsForUser(String user) {
        return removeFilteredPolicy(0, user);
    }

    /**
     * getPermissionsForUser gets permissions for a user or role.
     */
    public List<List<String>> getPermissionsForUser(String user) {
        return getFilteredPolicy(0, user);
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     */
    public boolean hasPermissionForUser(String user, String... permission) {
        List<String> params = new ArrayList<>();

        params.add(user);
        Collections.addAll(params, permission);

        return hasPolicy(params);
    }
}
