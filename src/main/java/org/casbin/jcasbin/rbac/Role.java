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

    public String toString() {
        StringBuilder names = new StringBuilder();
        for (int i = 0; i < roles.size(); i++) {
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
