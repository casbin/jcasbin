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

package org.casbin.jcasbin.rbac;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DefaultRoleManager provides interface to define the operations for managing roles.
 */
public class DefaultRoleManager implements RoleManager {
    private Map<String, Role> allRoles;
    private int level;

    public RoleManager Constructor() {
        return new DefaultRoleManager(10);
    }

    /**
     * DefaultRoleManager is the constructor for creating an instance of the
     * default RoleManager implementation.
     */
    public DefaultRoleManager(int level) {
        this.allRoles = new HashMap<String, Role>();
        this.level = level;
    }

    private boolean hasRole(String name) {
        return true;
    }

    private Role createRole(String name) {
        return null;
    }

    /**
     * addLink adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    @Override
    public void addLink(String name1, String name2, String... domain) {
    }

    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     */
    @Override
    public void deleteLink(String name1, String name2, String... domain) {
    }

    /**
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    @Override
    public boolean hasLink(String name1, String name2, String... domain) {
        return true;
    }

    /**
     * getRoles gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     */
    @Override
    public List<String> getRoles(String name, String... domain) {
        return null;
    }

    /**
     * getUsers gets the users that inherits a subject.
     */
    @Override
    public List<String> getUsers(String name) {
        return null;
    }

    /**
     * printRoles prints all the roles to log.
     */
    @Override
    public void printRoles() {
    }
}

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    private String name;
    private List<Role> roles;

    protected Role(String name) {
        this.name = name;
    }

    protected void addRole(Role role) {
    }

    protected void deleteRole(Role role) {
    }

    protected boolean hasRole(String name, int level) {
        return true;
    }

    protected boolean hasDirectRole(String name) {
        return true;
    }

    public String toString() {
        return "";
    }

    protected List<String> getRoles() {
        return null;
    }
}
