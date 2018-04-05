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

import javax.management.relation.Role;
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
        return true;
    }

    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     */
    public boolean deleteRoleForUser(String user, String role) {
        return true;
    }

    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     */
    public boolean deleteRolesForUser(String user) {
        return true;
    }

    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     */
    public boolean deleteUser(String user) {
        return true;
    }

    /**
     * deleteRole deletes a role.
     */
    public void deleteRole(String role) {
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     */
    public boolean deletePermission(String... permission) {
        return true;
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     */
    public boolean addPermissionForUser(String user, String... permission) {
        return true;
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     */
    public boolean deletePermissionForUser(String user, String... permission) {
        return true;
    }

    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     */
    public boolean deletePermissionsForUser(String user) {
        return true;
    }

    /**
     * getPermissionsForUser gets permissions for a user or role.
     */
    public String[][] getPermissionsForUser(String user) {
        return null;
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     */
    public boolean hasPermissionForUser(String user, String... permission) {
        return true;
    }
}
