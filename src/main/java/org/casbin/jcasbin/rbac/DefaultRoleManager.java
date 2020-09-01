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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;

import org.casbin.jcasbin.util.Util;

public class DefaultRoleManager implements RoleManager {
    private static String defaultDomain = "casbin::default";
    private Map<String, DomainRoles> allDomains;
    private int maxHierarchyLevel;

    private BiPredicate<String, String> matchingFunc;
    private BiPredicate<String, String> domainMatchingFunc;

    /**
     * DefaultRoleManager is the constructor for creating an instance of the default RoleManager
     * implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     */
    public DefaultRoleManager(int maxHierarchyLevel) {
        this(maxHierarchyLevel, null, null);
    }

    /**
     * In order to use a specific role name matching function, set explicitly the role manager on
     * the Enforcer and rebuild role links (you can optimize by using minimal enforcer constructor).
     * 
     * <pre>
     * final Enforcer e = new Enforcer("model.conf");
     * e.setAdapter(new FileAdapter("policies.csv"));
     * e.setRoleManager(new DefaultRoleManager(10, BuiltInFunctions::domainMatch));
     * e.loadPolicy();
     * </pre>
     * 
     * 
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     * @param matchingFunc a matcher for supporting pattern in g
     * @param domainMatchingPredicate a matcher for supporting domain pattern in g
     */
    public DefaultRoleManager(int maxHierarchyLevel, final BiPredicate<String, String> matchingFunc,
            final BiPredicate<String, String> domainMatchingFunc) {
        allDomains = new HashMap<>();
        this.maxHierarchyLevel = maxHierarchyLevel;

        this.matchingFunc = matchingFunc;
        this.domainMatchingFunc = domainMatchingFunc;
    }

    private String domainName(String... domain) {
        return domain.length == 0 ? defaultDomain : domain[0];
    }

    /**
     * Build temporary roles when a domain matching function is defined, else the domain or default
     * roles.
     * 
     * @param domain eventual domain
     * @return matched domain roles or domain roles
     */
    private DomainRoles getMatchingDomainRoles(String... domain) {
        if (domainMatchingFunc != null) {
            return generateTempRoles(domainName(domain));
        } else {
            return getOrCreateDomainRoles(domainName(domain));
        }
    }

    private DomainRoles generateTempRoles(final String domain) {
        allDomains.computeIfAbsent(domain, k -> new DomainRoles());

        final DomainRoles allRoles = new DomainRoles();
        final Set<String> patternDomains = getPatternMatchedDomainNames(domain);

        patternDomains.forEach(p -> {
            allDomains.computeIfAbsent(p, k -> new DomainRoles());
            createTempRolesForDomain(allRoles, p);
        });

        return allRoles;
    }

    private Set<String> getPatternMatchedDomainNames(final String domain) {
        final Set<String> patternDomains = new HashSet<>();
        patternDomains.add(domain);

        if (domainMatchingFunc != null) {
            allDomains.keySet().stream().filter(d -> domainMatchingFunc.test(domain, d)).forEach(patternDomains::add);
        }

        return patternDomains;
    }

    private void createTempRolesForDomain(final DomainRoles allRoles, final String domainName) {
        allDomains.get(domainName).forEach((roleName, role) -> {
            final Role role1 = allRoles.createRole(role.getName(), matchingFunc);
            role.getRoles().forEach(role2Name -> {
                final Role role3 = allRoles.createRole(role2Name, matchingFunc);
                role1.addRole(role3);
            });
        });
    }

    /**
     * clear clears all stored data and resets the role manager to the initial state.
     */
    @Override
    public void clear() {
        allDomains.clear();
        allDomains.put(defaultDomain, new DomainRoles());
    }

    private DomainRoles getOrCreateDomainRoles(final String domain) {
        return allDomains.computeIfAbsent(domain, k -> new DomainRoles());
    }

    /**
     * addLink adds the inheritance link between role: name1 and role: name2. aka role: name1
     * inherits role: name2. domain is a prefix to the roles.
     */
    @Override
    public void addLink(String name1, String name2, String... domain) {
        if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        final DomainRoles allRoles = getOrCreateDomainRoles(domainName(domain));

        final Role role1 = allRoles.getOrCreate(name1);
        final Role role2 = allRoles.getOrCreate(name2);
        role1.addRole(role2);
    }

    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2. aka role: name1
     * does not inherit role: name2 any more. domain is a prefix to the roles.
     */
    @Override
    public void deleteLink(String name1, String name2, String... domain) {
        if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        final DomainRoles allRoles = getOrCreateDomainRoles(domainName(domain));

        if (!allRoles.hasRole(name1) || !allRoles.hasRole(name2)) {
            throw new IllegalArgumentException("error: name1 or name2 does not exist");
        }

        final Role role1 = allRoles.getOrCreate(name1);
        final Role role2 = allRoles.getOrCreate(name2);

        role1.deleteRole(role2);
    }

    /**
     * hasLink determines whether role: name1 inherits role: name2. domain is a prefix to the roles.
     */
    @Override
    public boolean hasLink(String name1, String name2, String... domain) {
        isValidDomainOrThrow(domain);

        if (name1.equals(name2)) {
            return true;
        }

        final DomainRoles allRoles = getMatchingDomainRoles(domain);

        if (!allRoles.hasRole(name1, matchingFunc) || !allRoles.hasRole(name2, matchingFunc)) {
            return false;
        }

        Role role1 = allRoles.createRole(name1, matchingFunc);
        return role1.hasRole(name2, maxHierarchyLevel);
    }

    private void isValidDomainOrThrow(String... domain) {
        if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        if (domain.length >= 1 && "*".equals(domain[0])) {
            throw new IllegalArgumentException("error: domain can't be *");
        }
    }

    /**
     * getRoles gets the roles that a subject inherits. domain is a prefix to the roles.
     */
    @Override
    public List<String> getRoles(String name, String... domain) {
        if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        final DomainRoles allRoles = getMatchingDomainRoles(domain);

        if (!allRoles.hasRole(name, matchingFunc)) {
            throw new IllegalArgumentException("error: name does not exist");
        }

        return allRoles.createRole(name, matchingFunc).getRoles();
    }

    /**
     * getUsers gets the users that inherits a subject.
     */
    @Override
    public List<String> getUsers(String name, String... domain) {
        if (domain.length > 1) {
            throw new IllegalArgumentException("error: domain should be 1 parameter");
        }

        final DomainRoles allRoles = getMatchingDomainRoles(domain);

        if (!allRoles.hasRole(name, domainMatchingFunc)) {
            throw new IllegalArgumentException("error: name does not exist");
        }

        final List<String> names = new ArrayList<>();

        allRoles.forEach((roleName, role) -> {
            if (role.hasDirectRole(name)) {
                names.add(roleName);
            }
        });

        return names;
    }

    /**
     * printRoles prints all the roles to log.
     */
    @Override
    public void printRoles() {
        allDomains.forEach((domain, roles) -> roles.forEach((name, role) -> Util.logPrint(role.toString())));
    }
}
