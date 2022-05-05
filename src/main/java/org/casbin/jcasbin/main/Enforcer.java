// Copyright 2018 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.main;

import org.casbin.jcasbin.exception.CasbinNameNotExistException;
import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.casbin.jcasbin.rbac.RoleManager;

import java.util.*;

/**
 * Enforcer = ManagementEnforcer + RBAC API.
 */
public class Enforcer extends ManagementEnforcer {
    /**
     * Enforcer is the default constructor.
     */
    public Enforcer() {
        this("", "");
    }

    /**
     * Enforcer initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath the path of the model file.
     * @param policyFile the path of the policy file.
     */
    public Enforcer(String modelPath, String policyFile) {
        this(modelPath, new FileAdapter(policyFile));
    }

    /**
     * Enforcer initializes an enforcer with a database adapter.
     *
     * @param modelPath the path of the model file.
     * @param adapter the adapter.
     */
    public Enforcer(String modelPath, Adapter adapter) {
        this(newModel(modelPath, ""), adapter);
        this.modelPath = modelPath;
    }

    /**
     * Enforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m the model.
     * @param adapter the adapter.
     */
    public Enforcer(Model m, Adapter adapter) {
        this(m, adapter, true);
    }

    /**
     * Enforcer initializes an enforcer with a model, a database adapter and an enable log flag.
     *
     * @param m the model.
     * @param adapter the adapter.
     * @param enableLog whether to enable Casbin's log.
     */
    public Enforcer(Model m, Adapter adapter, boolean enableLog) {
        this.adapter = adapter;
        this.watcher = null;

        model = m;
        if (enableLog) {
            model.printModel();
        } else {
            this.enableLog(false);
        }
        fm = FunctionMap.loadFunctionMap();

        initialize();

        // fix: Enforcer pass FilteredAdapter will load all policy
        if (this.adapter != null && !isFiltered()) {
            loadPolicy();
        }
    }

    /**
     * Enforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    public Enforcer(Model m) {
        this(m, null);
    }

    /**
     * Enforcer initializes an enforcer with a model file.
     *
     * @param modelPath the path of the model file.
     */
    public Enforcer(String modelPath) {
        this(modelPath, "");
    }

    /**
     * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param modelPath the path of the model file.
     * @param policyFile the path of the policy file.
     * @param enableLog whether to enable Casbin's log.
     */
    public Enforcer(String modelPath, String policyFile, boolean enableLog) {
        this(newModel(modelPath, ""), new FileAdapter(policyFile), enableLog);
        this.modelPath =  modelPath;

    }

    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @return the roles that the user has.
     */
    public List<String> getRolesForUser(String name) {
        try {
            return model.model.get("g").get("g").rm.getRoles(name);
        } catch (CasbinNameNotExistException ignored) {
        }
        return Collections.emptyList();
    }

    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @return the users that has the role.
     */
    public List<String> getUsersForRole(String name) {
        try {
            return model.model.get("g").get("g").rm.getUsers(name);
        } catch (CasbinNameNotExistException ignored) {
        }
        return Collections.emptyList();
    }

    /**
     * hasRoleForUser determines whether a user has a role.
     *
     * @param name the user.
     * @param role the role.
     * @return whether the user has the role.
     */
    public boolean hasRoleForUser(String name, String role) {
        List<String> roles = getRolesForUser(name);

        boolean hasRole = false;
        for (String r : roles) {
            if (r.equals(role)) {
                hasRole = true;
                break;
            }
        }

        return hasRole;
    }

    /**
     * addRoleForUser adds a role for a user.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    public boolean addRoleForUser(String user, String role) {
        return addGroupingPolicy(user, role);
    }

    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    public boolean deleteRoleForUser(String user, String role) {
        return removeGroupingPolicy(user, role);
    }

    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    public boolean deleteRolesForUser(String user) {
        return removeFilteredGroupingPolicy(0, user);
    }

    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    public boolean deleteUser(String user) {
        return removeFilteredGroupingPolicy(0, user);
    }

    /**
     * deleteRole deletes a role.
     *
     * @param role the role.
     */
    public void deleteRole(String role) {
        removeFilteredGroupingPolicy(1, role);
        removeFilteredPolicy(0, role);
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean deletePermission(String... permission) {
        return removeFilteredPolicy(1, permission);
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean deletePermission(List<String> permission) {
        return deletePermission(permission.toArray(new String[0]));
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean addPermissionForUser(String user, String... permission) {
        List<String> params = new ArrayList<>();

        params.add(user);
        Collections.addAll(params, permission);

        return addPolicy(params);
    }

    /**
     * updatePermissionForUser updates a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user the user.
     * @param oldPermission the old permission.
     * @param newPermission the new permission.
     * @return succeeds or not.
     */
    public boolean updatePermissionForUser(String user, List<String> oldPermission, List<String> newPermission) {
        List<String> params1 = new ArrayList<>();
        List<String> params2 = new ArrayList<>();

        params1.add(user);
        params2.add(user);

        Collections.addAll(params1, oldPermission.toArray(new String[0]));
        Collections.addAll(params2, newPermission.toArray(new String[0]));

        return updatePolicy(params1, params2);
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean addPermissionForUser(String user, List<String> permission) {
        return addPermissionForUser(user, permission.toArray(new String[0]));
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean deletePermissionForUser(String user, String... permission) {
        List<String> params = new ArrayList<>();

        params.add(user);
        Collections.addAll(params, permission);

        return removePolicy(params);
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    public boolean deletePermissionForUser(String user, List<String> permission) {
        return deletePermissionForUser(user, permission.toArray(new String[0]));
    }

    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    public boolean deletePermissionsForUser(String user) {
        return removeFilteredPolicy(0, user);
    }

    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user   the user.
     * @param domain domain.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    public List<List<String>> getPermissionsForUser(String user, String... domain) {
        return getNamedPermissionsForUser("p", user, domain);
    }

    /**
     * getNamedPermissionsForUser gets permissions for a user or role by named policy.
     * @param pType     the name policy.
     * @param user      the user.
     * @param domain    domain.
     * @return the permissions.
     */
    List<List<String>> getNamedPermissionsForUser(String pType, String user, String... domain) {
        List<List<String>> permissions = new ArrayList<>();

        for (Map.Entry<String, Assertion> entry : model.model.get("p").entrySet()) {
            String ptype = entry.getKey();
            if (!ptype.equals(pType)) continue;
            permissions.addAll(getFilteredNamedPolicy(pType, 0, getPermissionsPackFunc(entry, ptype, user, domain)));
        }

        return permissions;
    }

    /**
     * get the match field value, used to field filters.
     * @param entry  the entry of pType:assertion.
     * @param pType  the named policy
     * @param user   the user.
     * @param domain domain.
     * @return the match field.
     */
    private String[] getPermissionsPackFunc(Map.Entry<String, Assertion> entry, String pType, String user, String... domain) {
        Assertion ast = entry.getValue();
        String[] args = new String[ast.tokens.length];
        args[0] = user;
        int index = getDomainIndex(pType);
        if (domain.length > 0 && index < ast.tokens.length) {
            args[index] = domain[0];
        }
        return args;
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    public boolean hasPermissionForUser(String user, String... permission) {
        List<String> params = new ArrayList<>();

        params.add(user);
        Collections.addAll(params, permission);

        return hasPolicy(params);
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    public boolean hasPermissionForUser(String user, List<String> permission) {
        return hasPermissionForUser(user, permission.toArray(new String[0]));
    }

    /**
     * getRolesForUserInDomain gets the roles that a user has inside a domain.
     *
     * @param name the user.
     * @param domain the domain.
     * @return the roles that the user has in the domain.
     */
    public List<String> getRolesForUserInDomain(String name, String domain) {
        try {
            return model.model.get("g").get("g").rm.getRoles(name, domain);
        } catch (CasbinNameNotExistException ignored) {
        }
        return Collections.emptyList();
    }

    /**
     * getPermissionsForUserInDomain gets permissions for a user or role inside a domain.
     *
     * @param user the user.
     * @param domain the domain.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    public List<List<String>> getPermissionsForUserInDomain(String user, String domain) {
        return getFilteredPolicy(0, user, domain);
    }

    /**
     * addRoleForUserInDomain adds a role for a user inside a domain.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    public boolean addRoleForUserInDomain(String user, String role, String domain) {
        return addGroupingPolicy(user, role, domain);
    }

    /**
     * deleteRoleForUserInDomain deletes a role for a user inside a domain.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    public boolean deleteRoleForUserInDomain(String user, String role, String domain) {
        return removeGroupingPolicy(user, role, domain);
    }

    /**
     * getImplicitRolesForUser gets implicit roles that a user has.
     * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
     * For example:
     * g, alice, role:admin
     * g, role:admin, role:user
     * <p>
     * getRolesForUser("alice") can only get: ["role:admin"].
     * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
     *
     * @param name   the user.
     * @param domain the user's domain.
     * @return implicit roles that a user has.
     */
    public List<String> getImplicitRolesForUser(String name, String... domain) {
        List<String> res = new ArrayList<>();
        Deque<String> queue = new LinkedList<>();
        queue.offerLast(name);

        while (!queue.isEmpty()) {
            name = queue.pollFirst();
            for (RoleManager rm : rmMap.values()) {
                List<String> roles = rm.getRoles(name, domain);
                for (String role : roles) {
                    if (res.contains(role)) continue;
                    res.add(role);
                    queue.offerLast(role);
                }
            }
        }

        return res;
    }

    /**
     * getImplicitUsersForRole gets implicit users for a role.
     *
     * @param name   the role.
     * @param domain the role's domain.
     * @return implicit users that a role has.
     */
    public List<String> getImplicitUsersForRole(String name, String... domain) {
        Deque<String> queue = new LinkedList<>();
        queue.offerLast(name);
        List<String> res = new ArrayList<>();

        while (!queue.isEmpty()) {
            name = queue.pollFirst();
            for (RoleManager rm : rmMap.values()) {
                try {
                    List<String> users = rm.getUsers(name, domain);
                    for (String user : users) {
                        if (res.contains(user)) continue;
                        res.add(user);
                        queue.offerLast(user);
                    }
                } catch (CasbinNameNotExistException ignored) {
                }
            }
        }

        return res;
    }

    /**
     * getImplicitPermissionsForUser gets implicit permissions for a user or role.
     * Compared to getPermissionsForUser(), this function retrieves permissions for inherited roles.
     * For example:
     * p, admin, data1, read
     * p, alice, data2, read
     * g, alice, admin
     * <p>
     * getPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
     * But getImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
     *
     * @param user   the user.
     * @param domain the user's domain.
     * @return implicit permissions for a user or role.
     */
    public List<List<String>> getImplicitPermissionsForUser(String user, String... domain) {
        return getNamedImplicitPermissionsForUser("p", user, domain);
    }

    /**
     * GetNamedImplicitPermissionsForUser gets implicit permissions for a user or role by named policy.
     * Compared to GetNamedPermissionsForUser(), this function retrieves permissions for inherited roles.
     * For example:
     * p, admin, data1, read
     * p2, admin, create
     * g, alice, admin
     * <p>
     * GetImplicitPermissionsForUser("alice") can only get: [["admin", "data1", "read"]], whose policy is default policy "p".
     * But you can specify the named policy "p2" to get: [["admin", "create"]] by GetNamedImplicitPermissionsForUser("p2","alice").
     *
     * @param pType     the name policy.
     * @param user      the user.
     * @param domain    the user's domain.
     * @return implicit permissions for a user or role by named policy.
     */
    public List<List<String>> getNamedImplicitPermissionsForUser(String pType, String user, String... domain) {
        List<String> roles = new ArrayList<>();
        roles.add(user);
        roles.addAll(getImplicitRolesForUser(user, domain));
        List<List<String>> res = new ArrayList<>();
        for (String role : roles) {
            res.addAll(this.getNamedPermissionsForUser(pType, role, domain));
        }
        return res;
    }


    /**
     * getImplicitPermissionsForUserInDomain gets implicit permissions for a user or role in domain.
     *
     * @param user the user.
     * @param domain the domain.
     * @return implicit permissions for a user or role in domain.
     */
    public List<List<String>> getImplicitPermissionsForUserInDomain(String user, String domain) {
        List<String> roles = new ArrayList<>();
        roles.add(user);
        roles.addAll(this.getImplicitRolesForUser(user, domain));
        List<List<String>> res = new ArrayList<>();
        for (String n : roles) {
            res.addAll(this.getPermissionsForUserInDomain(n, domain));
        }
        return res;
    }

    /**
     * BatchEnforce enforce in batches
     *
     * @param rules the rules.
     * @return the results
     */
    public List<Boolean> batchEnforce(List<List<String>> rules) {
        List<Boolean> results = new ArrayList<>();
        for (List<String> rule:rules) {
            boolean result = this.enforce(rule.get(0), rule.get(1), rule.get(2));
            results.add(result);
        }
        return results;
    }

    /**
     * batchEnforceWithMatcher enforce with matcher in batches
     *
     * @param matcher the custom matcher.
     * @param rules   the rules.
     * @return the results
     */
    public List<Boolean> batchEnforceWithMatcher(String matcher, List<List<String>> rules) {
        List<Boolean> results = new ArrayList<>();
        for (List<String> rule : rules) {
            boolean result = this.enforceWithMatcher(matcher, rule.get(0), rule.get(1), rule.get(2));
            results.add(result);
        }
        return results;
    }
}
