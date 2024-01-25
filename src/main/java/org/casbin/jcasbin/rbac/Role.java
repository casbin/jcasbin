// Copyright 2020 The casbin Authors. All Rights Reserved.
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

import java.util.*;

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    private final String name;
    final Map<String, Role> roles;
    private final Map<String, Role> users;
    private final Map<String, Role> matched;
    private final Map<String, Role> matchedBy;

    protected Role(String name) {
        this.name = name;
        this.roles = new HashMap<>();
        this.users = new HashMap<>();
        this.matched = new HashMap<>();
        this.matchedBy = new HashMap<>();
    }

    String getName() {
        return name;
    }

    void addRole(Role role) {
        this.roles.put(role.name, role);
        role.addUser(this);
    }

    void removeRole(Role role) {
        this.roles.remove(role.name);
        role.removeUser(this);
    }

    private void addUser(Role user) {
        this.users.put(user.name, user);
    }

    private void removeUser(Role user) {
        this.users.remove(user.name);
    }

    void addMatch(Role role) {
        this.matched.put(role.name, role);
        role.matchedBy.put(this.name, this);
    }

    void removeMatch(Role role) {
        this.matched.remove(role.name);
        role.matchedBy.remove(this.name);
    }

    void removeMatches() {
        Iterator<Map.Entry<String, Role>> iterator = this.matchedBy.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Role> entry = iterator.next();
            Role role = entry.getValue();
            role.matched.remove(this.name);
            iterator.remove();
        }
    }

    @Override
    public String toString() {
        List<String> roles = getRoles();

        if (roles.size() == 0) {
            return "";
        }

        StringBuilder names = new StringBuilder();
        names.append(this.name).append(" < ");

        if (roles.size() != 1) {
            names.append("(");
        }

        for (int i = 0; i < roles.size(); i++) {
            String role = roles.get(i);
            if (i == 0) {
                names.append(role);
            } else {
                names.append(", ").append(role);
            }
        }

        if (roles.size() != 1) {
            names.append(")");
        }

        return names.toString();
    }

    List<String> getRoles() {
        return new ArrayList<>(getAllRoles().keySet());
    }

    List<String> getUsers() {
        return new ArrayList<>(getAllUsers().keySet());
    }

    Map<String, Role> getAllRoles() {
        Map<String, Role> allRoles = new HashMap<>(this.roles);
        this.roles.values().forEach(role -> allRoles.putAll(role.matched));
        this.matchedBy.values().forEach(role -> allRoles.putAll(role.roles));
        return allRoles;
    }

    Map<String, Role> getAllUsers() {
        Map<String, Role> allUsers = new HashMap<>(this.users);
        this.users.values().forEach(role -> allUsers.putAll(role.matched));
        this.matchedBy.values().forEach(role -> allUsers.putAll(role.users));
        return allUsers;
    }
}
