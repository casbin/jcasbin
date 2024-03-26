// Copyright 2024 The casbin Authors. All Rights Reserved.
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
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.function.Function;

public class ConditionalRoleManager extends DefaultRoleManager{
    public ConditionalRoleManager(int maxHierarchyLevel) {
        super(maxHierarchyLevel);
    }

    public ConditionalRoleManager(int maxHierarchyLevel, BiPredicate<String, String> matchingFunc, BiPredicate<String, String> domainMatchingFunc) {
        super(maxHierarchyLevel, matchingFunc, domainMatchingFunc);
    }

    public synchronized boolean hasLink(String name1, String name2, String... domains) {
        if (name1.equals(name2) || (this.matchingFunc != null && this.matchingFunc.test(name1, name2))) {
            return true;
        }

        boolean userCreated = !this.allRoles.containsKey(name1);
        boolean roleCreated = !this.allRoles.containsKey(name2);
        Role user = getRole(name1);
        Role role = getRole(name2);

        Map<String, Role> roles = new HashMap<>();
        roles.put(user.getName(), user);

        try {
            return hasLinkHelper(role.getName(), roles, this.maxHierarchyLevel, domains);
        } finally {
            if (userCreated) {
                removeRole(user.getName());
            }
            if (roleCreated) {
                removeRole(role.getName());
            }
        }
    }

    public boolean hasLinkHelper(String targetName, Map<String, Role> roles, int level, String... domains) {
        if (level < 0 || roles.isEmpty()) {
            return false;
        }
        Map<String, Role> nextRoles = new HashMap<>();
        for (Role role : roles.values()) {
            if (targetName.equals(role.getName()) || (matchingFunc != null && match(role.getName(), targetName))) {
                return true;
            }
            role.rangeRoles(new Consumer<Role>() {
                @Override
                public void accept(Role nextRole) {
                    getNextRoles(role, nextRole, domains, nextRoles);
                }
            });
        }
        return hasLinkHelper(targetName, nextRoles, level - 1, domains);
    }

    public boolean getNextRoles(Role currentRole, Role nextRole, String[] domains, Map<String, Role> nextRoles) {
        boolean passLinkConditionFunc = true;
        Exception err = null;

        // If LinkConditionFunc exists, it needs to pass the verification to get nextRole
        if (domains.length == 0) {
            Function<String[], Boolean> linkConditionFunc = getLinkConditionFunc(currentRole.getName(), nextRole.getName());
            if (linkConditionFunc != null) {
                List<String> params = getLinkConditionFuncParams(currentRole.getName(), nextRole.getName(), domains);
                try {
                    passLinkConditionFunc = linkConditionFunc.apply(params.toArray(new String[0]));
                } catch (Exception e) {
                    err = e;
                }
            }
        } else {
            Function<String[], Boolean> linkConditionFunc = getDomainLinkConditionFunc(currentRole.getName(), nextRole.getName(), domains[0]);
            if (linkConditionFunc != null) {
                List<String> params = getLinkConditionFuncParams(currentRole.getName(), nextRole.getName(), domains);
                try {
                    passLinkConditionFunc = linkConditionFunc.apply(params.toArray(new String[0]));
                } catch (Exception e) {
                    err = e;
                }
            }
        }

        if (err != null) {
            System.err.println("hasLinkHelper LinkCondition Error");
            err.printStackTrace();
            return false;
        }

        if (passLinkConditionFunc) {
            nextRoles.put(nextRole.getName(), nextRole);
        }

        return true;
    }

    /**
     * getLinkConditionFunc get LinkConditionFunc based on userName, roleName
     */
    public Function<String[], Boolean> getLinkConditionFunc(String userName, String roleName){
        return getDomainLinkConditionFunc(userName, roleName, "");
    }

    /**
     * getDomainLinkConditionFunc get LinkConditionFunc based on userName, roleName, domain
     */
    public Function<String[], Boolean> getDomainLinkConditionFunc(String userName, String roleName, String domain){
        Role user = getRole(userName);
        Role role = getRole(roleName);

        if (user == null) {
            return null;
        }
        if (role == null) {
            return null;
        }

        return user.getLinkConditionFunc(role, domain);
    }

    /**
     * getLinkConditionFuncParams gets parameters of LinkConditionFunc based on userName, roleName, domain
     */
    public List<String> getLinkConditionFuncParams(String userName, String roleName, String[] domain){
        boolean userCreated = !this.allRoles.containsKey(userName);
        boolean roleCreated = !this.allRoles.containsKey(roleName);
        Role user = getRole(userName);
        Role role = getRole(roleName);

        if (userCreated)
            removeRole(user.getName());
        if (roleCreated)
            removeRole(role.getName());

        String domainName = "";
        if (domain.length != 0) {
            domainName = domain[0];
        }

        String[] params = user.getLinkConditionFuncParams(role, domainName);
        if (params != null){
            return Arrays.asList(params);
        } else {
            return null;
        }
    }

    /**
     * addLinkConditionFunc is based on userName, roleName, add LinkConditionFunc
     */
    public void addLinkConditionFunc(String userName, String roleName, Function<String[], Boolean> fn){
        addDomainLinkConditionFunc(userName, roleName, "", fn);
    }

    /**
     * addDomainLinkConditionFunc is based on userName, roleName, domain, add LinkConditionFunc
     */
    public void addDomainLinkConditionFunc(String userName, String roleName, String domain, Function<String[], Boolean> fn){
        Role user = getRole(userName);
        Role role = getRole(roleName);

        user.addLinkConditionFunc(role, domain, fn);
    }

    /**
     * SetLinkConditionFuncParams sets parameters of LinkConditionFunc based on userName, roleName, domain
     */
    public void setLinkConditionFuncParams(String userName, String roleName, String... params) {
        setDomainLinkConditionFuncParams(userName, roleName, "", params);
    }

    /**
     * SetDomainLinkConditionFuncParams sets parameters of LinkConditionFunc based on userName, roleName, domain
     */
    public void setDomainLinkConditionFuncParams(String userName, String roleName, String domain, String... params) {
        Role user = getRole(userName);
        Role role = getRole(roleName);

        user.setLinkConditionFuncParams(role, domain, params);
    }
}
