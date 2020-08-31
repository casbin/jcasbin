package org.casbin.jcasbin.rbac;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.function.BiPredicate;

/**
 * Represents all roles in a domain
 */
class DomainRoles {
    private Map<String, Role> roles = new HashMap<>();

    public void forEach(BiConsumer<? super String, ? super Role> action) {
        roles.forEach(action);
    }

    public boolean hasRole(final String name) {
        return this.hasRole(name, null);
    }

    public boolean hasRole(final String name, BiPredicate<String, String> matchingFunc) {
        if (matchingFunc != null) {
            return roles.keySet().stream().anyMatch(r -> matchingFunc.test(name, r));
        } else {
            return roles.containsKey(name);
        }
    }

    public Role createRole(final String name, BiPredicate<String, String> matchingFunc) {
        final Role role = roles.computeIfAbsent(name, Role::new);

        if (matchingFunc != null) {
            roles.entrySet().stream().filter(roleEntry -> isRoleEntryMatchExists(roleEntry, name, matchingFunc))
                    .forEach(roleEntry -> role.addRole(roleEntry.getValue()));
        }

        return role;
    }

    private boolean isRoleEntryMatchExists(final Entry<String, Role> roleEntry, final String name, final BiPredicate<String, String> matchingFunc) {
        return matchingFunc.test(name, roleEntry.getKey()) && !name.equals(roleEntry.getKey());
    }

    public Role getOrCreate(final String name) {
        return roles.computeIfAbsent(name, Role::new);
    }
}