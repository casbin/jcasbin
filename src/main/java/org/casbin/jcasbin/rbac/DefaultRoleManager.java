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

import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultRoleManager implements RoleManager {
    private Map<String, Role> allRoles;
    private int maxHierarchyLevel;

    /**
     * DefaultRoleManager is the constructor for creating an instance of the
     * default RoleManager implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     */
    public DefaultRoleManager(int maxHierarchyLevel) {
        allRoles = new HashMap<>();
        this.maxHierarchyLevel = maxHierarchyLevel;
    }

    private boolean hasRole(String name) {
        return allRoles.containsKey(name);
    }

    private Role createRole(String name) {
        if (hasRole(name)) {
            return allRoles.get(name);
        } else {
            Role role = new Role(name);
            allRoles.put(name, role);
            return role;
        }
    }

    /**
     * clear clears all stored data and resets the role manager to the initial state.
     */
    @Override
    public void clear() {
        allRoles.clear();
    }

    /**
     * addLink adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    @Override
    public void addLink(String name1, String name2, String... domain) {
        if (domain.length == 1) {
            name1 = domain[0] + "::" + name1;
            name2 = domain[0] + "::" + name2;
        } else if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        Role role1 = createRole(name1);
        Role role2 = createRole(name2);
        role1.addRole(role2);
    }

    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     */
    @Override
    public void deleteLink(String name1, String name2, String... domain) {
        if (domain.length == 1) {
            name1 = domain[0] + "::" + name1;
            name2 = domain[0] + "::" + name2;
        } else if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        if (!hasRole(name1) || !hasRole(name2)) {
            throw new IllegalArgumentException("error: name1 or name2 does not exist");
        }

        Role role1 = createRole(name1);
        Role role2 = createRole(name2);
        role1.deleteRole(role2);
    }

    /**
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    @Override
    public boolean hasLink(String name1, String name2, String... domain) {
        if (domain.length == 1) {
            name1 = domain[0] + "::" + name1;
            name2 = domain[0] + "::" + name2;
        } else if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        if (name1.equals(name2)) {
            return true;
        }

        if (!hasRole(name1) || !hasRole(name2)) {
            return false;
        }

        Role role1 = createRole(name1);
        return role1.hasRole(name2, maxHierarchyLevel);
    }

    /**
     * getRoles gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     */
    @Override
    public List<String> getRoles(String name, String... domain) {
        if (domain.length == 1) {
            name = domain[0] + "::" + name;
        } else if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        if (!hasRole(name)) {
            throw new IllegalArgumentException("error: name does not exist");
        }

        List<String> roles = createRole(name).getRoles();
        if (domain.length == 1) {
            for (int i = 0; i < roles.size(); i ++) {
                roles.set(i, roles.get(i).substring(domain[0].length() + 2, roles.get(i).length()));
            }
        }
        return roles;
    }

    /**
     * getUsers gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     */
    @Override
    public List<String> getUsers(String name) {
        if (!hasRole(name)) {
            throw new IllegalArgumentException("error: name does not exist");
        }

        List<String> names = new ArrayList<>();
        for (Role role : allRoles.values()) {
            if (role.hasDirectRole(name)) {
                names.add(role.name);
            }
        }
        return names;
    }

    /**
     * printRoles prints all the roles to log.
     */
    @Override
    public void printRoles() {
        for (Role role : allRoles.values()) {
            Util.logPrint(role.toString());
        }
    }
}

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    String name;
    private List<Role> roles;

    protected Role(String name) {
        this.name = name;
        roles = new ArrayList<>();
    }

    void addRole(Role role) {
        for (Role r : roles) {
            if (r.name.equals(role.name)) {
                return;
            }
        }

        roles.add(role);
    }

    void deleteRole(Role role) {
        List<Role> toRemove = new ArrayList<>();
        for (Role r : roles) {
            if (r.name.equals(role.name)) {
                toRemove.add(r);
            }
        }
        roles.removeAll(toRemove);
    }

    boolean hasRole(String name, int hierarchyLevel) {
        if (this.name.equals(name)) {
            return true;
        }

        if (hierarchyLevel <= 0) {
            return false;
        }

        for (Role role : roles) {
            if (role.hasRole(name, hierarchyLevel - 1)) {
                return true;
            }
        }
        return false;
    }

    boolean hasDirectRole(String name) {
        for (Role r : roles) {
            if (r.name.equals(name)) {
                return true;
            }
        }

        return false;
    }

    public String toString() {
        StringBuilder names = new StringBuilder();
        for (int i = 0; i < roles.size(); i ++) {
            Role role = roles.get(i);
            if (i == 0) {
                names.append(role.name);
            } else {
                names.append(", " + role.name);
            }
        }
        return name + " < " + names;
    }

    List<String> getRoles() {
        List<String> names = new ArrayList<>();
        for (Role r : roles) {
            names.add(r.name);
        }
        return names;
    }
}
