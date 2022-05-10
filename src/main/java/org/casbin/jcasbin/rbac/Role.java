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

import java.util.ArrayList;
import java.util.List;

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    private String name;
    private List<Role> roles;

    protected Role(String name) {
        this.name = name;
        roles = new ArrayList<>();
    }

    String getName() {
        return name;
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
        for (Role r : roles) {
            if (r.name.equals(role.name)) {
                roles.remove(r);
                return;
            }
        }
    }

    boolean hasRole(String name, int hierarchyLevel) {
        if (this.name.equals(name)) {
            return true;
        }

        if (hierarchyLevel <= 0) {
            return false;
        }

        return roles.stream().anyMatch(r -> r.hasRole(name, hierarchyLevel - 1));
    }

    boolean hasDirectRole(String name) {
        for (Role r : roles) {
            if (r.name.equals(name)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public String toString() {
        StringBuilder names = new StringBuilder();
        for (int i = 0; i < roles.size(); i++) {
            Role role = roles.get(i);
            if (i == 0) {
                names.append(role.name);
            } else {
                names.append(", ").append(role.name);
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
