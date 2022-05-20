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
            return roles.keySet().stream().anyMatch(r -> matchingFunc.test(name, r) || r.equals(name));
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
