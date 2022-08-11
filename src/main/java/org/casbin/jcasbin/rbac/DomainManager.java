// Copyright 2022 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.util.SyncedLRUCache;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.BiPredicate;

/**
 * @author Yixiang Zhao (@seriouszyx)
 **/
public class DomainManager implements RoleManager {
    private static final String DEFAULT_DOMAIN = "casbin::default";
    private Map<String, DefaultRoleManager> rmMap;
    private int maxHierarchyLevel;
    private BiPredicate<String, String> matchingFunc;
    private BiPredicate<String, String> domainMatchingFunc;
    private SyncedLRUCache<String, Boolean> domainMatchingFuncCache;

    public DomainManager(int maxHierarchyLevel) {
        this(maxHierarchyLevel, null, null);
    }

    public DomainManager(int maxHierarchyLevel, final BiPredicate<String, String> matchingFunc,
                         final BiPredicate<String, String> domainMatchingFunc) {
        clear();
        this.maxHierarchyLevel = maxHierarchyLevel;
        this.matchingFunc = matchingFunc;
        this.domainMatchingFunc = domainMatchingFunc;
    }

    public void addMatchingFunc(String name, BiPredicate<String, String> matchingFunc) {
        this.matchingFunc = matchingFunc;
        this.rmMap.values().forEach(rm -> rm.addMatchingFunc(name, matchingFunc));
    }

    public void addDomainMatchingFunc(String name, BiPredicate<String, String> domainMatchingFunc) {
        this.domainMatchingFunc = domainMatchingFunc;
        rebuild();
    }

    /**
     * rebuild clears the map of RoleManagers
     */
    private void rebuild() {
        Map<String, DefaultRoleManager> rmMap = new HashMap<>(this.rmMap);
        clear();
        rmMap.forEach((domain, rm) -> {
            rm.allRoles.values().forEach(user -> {
                user.roles.keySet().forEach(roleName -> addLink(user.getName(), roleName, domain));
            });
        });
    }

    private String domainName(String... domain) {
        return domain.length == 0 ? DEFAULT_DOMAIN : domain[0];
    }

    private DefaultRoleManager getRoleManager(String domain, boolean store) {
        DefaultRoleManager rm = this.rmMap.get(domain);
        if (rm == null) {
            rm = new DefaultRoleManager(this.maxHierarchyLevel, this.matchingFunc, null);
            if (store) {
                this.rmMap.put(domain, rm);
            }
            if (this.domainMatchingFunc != null) {
                for (Map.Entry<String, DefaultRoleManager> entry : this.rmMap.entrySet()) {
                    String domain2 = entry.getKey();
                    DefaultRoleManager rm2 = entry.getValue();
                    if (!domain.equals(domain2) && match(domain, domain2)) {
                        rm.copyFrom(rm2);
                    }
                }
            }
        }
        return rm;
    }

    private boolean match(String str, String pattern) {
        String cacheKey =  String.join("$$", str, pattern);
        Boolean matched = this.domainMatchingFuncCache.get(cacheKey);
        if (matched == null) {
            if (this.domainMatchingFunc != null) {
                matched = this.domainMatchingFunc.test(str, pattern);
            } else {
                matched = str.equals(pattern);
            }
            this.domainMatchingFuncCache.put(cacheKey, matched);
        }
        return matched;
    }

    @Override
    public void clear() {
        this.rmMap = new HashMap<>();
        this.domainMatchingFuncCache = new SyncedLRUCache<>(100);
    }

    @Override
    public void addLink(String name1, String name2, String... domain) {
        DefaultRoleManager roleManager = getRoleManager(domainName(domain), true);
        roleManager.addLink(name1, name2, domain);

        if (this.domainMatchingFunc != null) {
            this.rmMap.forEach((domain2, rm) -> {
                if (!domainName(domain).equals(domain2) && match(domain2, domainName(domain))) {
                    rm.addLink(name1, name2, domain);
                }
            });
        }
    }

    @Override
    public void deleteLink(String name1, String name2, String... domain) {
        DefaultRoleManager roleManager = getRoleManager(domainName(domain), true);
        roleManager.deleteLink(name1, name2, domain);

        if (this.domainMatchingFunc != null) {
            this.rmMap.forEach((domain2, rm) -> {
                if (!domainName(domain).equals(domain2) && match(domain2, domainName(domain))) {
                    rm.deleteLink(name1, name2, domain);
                }
            });
        }
    }

    @Override
    public boolean hasLink(String name1, String name2, String... domain) {
        DefaultRoleManager roleManager = getRoleManager(domainName(domain), false);
        return roleManager.hasLink(name1, name2, domain);
    }

    @Override
    public List<String> getRoles(String name, String... domain) {
        DefaultRoleManager roleManager = getRoleManager(domainName(domain), false);
        return roleManager.getRoles(name, domain);
    }

    @Override
    public List<String> getUsers(String name, String... domain) {
        DefaultRoleManager roleManager = getRoleManager(domainName(domain), false);
        return roleManager.getUsers(name, domain);
    }

    @Override
    public String toString() {
        List<String> roles = new ArrayList<>();
        this.rmMap.forEach((domain, rm) -> {
            List<String> domainRoles = new ArrayList<>();
            rm.allRoles.values().forEach(role -> {
                if (!"".equals(role.toString())) {
                    domainRoles.add(role.toString());
                }
            });
            roles.add(domain + ": " + String.join(", ", domainRoles));
        });
        return String.join("\n", roles);
    }

    @Override
    public void printRoles() {
        Util.logPrint(toString());
    }
}
