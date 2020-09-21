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

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Watcher;

import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * SyncedEnforcer = ManagementEnforcer + RBAC API.
 */
public class SyncedEnforcer extends Enforcer {

    private final static ReadWriteLock READ_WRITE_LOCK = new ReentrantReadWriteLock();

    /**
     * ;
     * SyncedEnforcer is the default constructor.
     */
    public SyncedEnforcer() {
        super();
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     */
    public SyncedEnforcer(String modelPath, String policyFile) {
        super(modelPath, policyFile);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a database adapter.
     *
     * @param modelPath the path of the model file.
     * @param adapter   the adapter.
     */
    public SyncedEnforcer(String modelPath, Adapter adapter) {
        super(modelPath, adapter);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m       the model.
     * @param adapter the adapter.
     */
    public SyncedEnforcer(Model m, Adapter adapter) {
        super(m, adapter);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    public SyncedEnforcer(Model m) {
        super(m);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model file.
     *
     * @param modelPath the path of the model file.
     */
    public SyncedEnforcer(String modelPath) {
        super(modelPath);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     * @param enableLog  whether to enable Casbin's log.
     */
    public SyncedEnforcer(String modelPath, String policyFile, boolean enableLog) {
        super(modelPath, policyFile, enableLog);
    }

    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    public void setWatcher(Watcher watcher) {
        this.watcher = watcher;
        watcher.setUpdateCallback(this::loadPolicy);
    }

    /**
     * clearPolicy clears all policy.
     */
    public void clearPolicy() {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            super.clearPolicy();
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * loadPolicy reloads the policy from file/database.
     */
    public void loadPolicy() {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            super.loadPolicy();
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    public void loadFilteredPolicy(Object filter) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            super.loadFilteredPolicy(filter);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    public void savePolicy() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            super.savePolicy();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
     */
    public void buildRoleLinks() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            super.buildRoleLinks();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    public boolean enforce(Object... rvals) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.enforce(rvals);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     *
     * @return all the subjects in "p" policy rules. It actually collects the
     *         0-index elements of "p" policy rules. So make sure your subject
     *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
     */
    public List<String> getAllSubjects() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getAllSubjects();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     *
     * @return all the objects in "p" policy rules. It actually collects the
     *         1-index elements of "p" policy rules. So make sure your object
     *         is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllObjects() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getAllObjects();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getAllNamedObjects gets the list of objects that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the objects in policy rules of the ptype type. It actually
     *         collects the 1-index elements of the policy rules. So make sure
     *         your object is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllNamedObjects(String ptype) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getAllNamedObjects(ptype);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getAllActions gets the list of actions that show up in the current policy.
     *
     * @return all the actions in "p" policy rules. It actually collects
     *         the 2-index elements of "p" policy rules. So make sure your action
     *         is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllActions() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getAllActions();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * GetAllNamedActions gets the list of actions that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the actions in policy rules of the ptype type. It actually
     *         collects the 2-index elements of the policy rules. So make sure
     *         your action is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllNamedActions(String ptype) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getAllNamedActions(ptype);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     *
     * @return all the roles in "g" policy rules. It actually collects
     *         the 1-index elements of "g" policy rules. So make sure your
     *         role is the 1-index element, like (sub, role).
     *         Duplicates are removed.
     */
    public List<String> getAllRoles() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getAllRoles();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getAllNamedRoles gets the list of roles that show up in the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make
     *         sure your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    public List<String> getAllNamedRoles(String ptype) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getAllNamedRoles(ptype);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getPolicy gets all the authorization rules in the policy.
     *
     * @return all the "p" policy rules.
     */
    public List<List<String>> getPolicy() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getPolicy();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules.
     */
    public List<List<String>> getFilteredPolicy(int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getFilteredPolicy(fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return the "p" policy rules of the specified ptype.
     */
    public List<List<String>> getNamedPolicy(String ptype) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getNamedPolicy(ptype);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules of the specified ptype.
     */
    public List<List<String>> getFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getFilteredNamedPolicy(ptype, fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @return all the "g" policy rules.
     */
    public List<List<String>> getGroupingPolicy() {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getGroupingPolicy();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @return the roles that the user has.
     */
    @Override
    public List<String> getRolesForUser(String name) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getRolesForUser(name);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
                          means not to match this field.
     * @return the filtered "g" policy rules.
     */
    public List<List<String>> getFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getFilteredGroupingPolicy(fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return the "g" policy rules of the specified ptype.
     */
    public List<List<String>> getNamedGroupingPolicy(String ptype) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getNamedGroupingPolicy(ptype);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "g" policy rules of the specified ptype.
     */
    public List<List<String>> getFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasPolicy(List<String> params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasPolicy(params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasPolicy(String... params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasPolicy(params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedPolicy(String ptype, List<String> params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasNamedPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }
    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedPolicy(String ptype, String... params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasNamedPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addPolicy(List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addPolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addPolicy(String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addPolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedPolicy(String ptype, List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addNamedPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * AddNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedPolicy(String ptype, String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addNamedPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removePolicy(List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removePolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removePolicy(String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removePolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredPolicy(int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeFilteredPolicy(fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedPolicy(String ptype, List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeNamedPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedPolicy(String ptype, String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeNamedPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeFilteredNamedPolicy(ptype, fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasGroupingPolicy(List<String> params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasGroupingPolicy(params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    public boolean hasGroupingPolicy(String... params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasGroupingPolicy(params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedGroupingPolicy(String ptype, List<String> params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasNamedGroupingPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    public boolean hasNamedGroupingPolicy(String ptype, String... params) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasNamedGroupingPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPolicy(List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addGroupingPolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean addGroupingPolicy(String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addGroupingPolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPolicy(String ptype, List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addNamedGroupingPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean addNamedGroupingPolicy(String ptype, String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addNamedGroupingPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removeGroupingPolicy(List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeGroupingPolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    public boolean removeGroupingPolicy(String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeGroupingPolicy(params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeFilteredGroupingPolicy(fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedGroupingPolicy(String ptype, List<String> params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeNamedGroupingPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    public boolean removeNamedGroupingPolicy(String ptype, String... params) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeNamedGroupingPolicy(ptype, params);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.removeFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @return the users that has the role.
     */
    @Override
    public List<String> getUsersForRole(String name) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getUsersForRole(name);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasRoleForUser determines whether a user has a role.
     *
     * @param name the user.
     * @param role the role.
     * @return whether the user has the role.
     */
    @Override
    public boolean hasRoleForUser(String name, String role) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasRoleForUser(name, role);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * addRoleForUser adds a role for a user.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    @Override
    public boolean addRoleForUser(String user, String role) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addRoleForUser(user, role);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteRoleForUser(String user, String role) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteRoleForUser(user, role);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteRolesForUser(String user) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteRolesForUser(user);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteUser(String user) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteUser(user);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRole deletes a role.
     *
     * @param role the role.
     */
    @Override
    public void deleteRole(String role) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            super.deleteRole(role);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermission(String... permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermission(permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermission(List<String> permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermission(permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean addPermissionForUser(String user, String... permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean addPermissionForUser(String user, List<String> permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermissionForUser(String user, String... permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermissionForUser(String user, List<String> permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermissionsForUser(String user) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermissionsForUser(user);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user the user.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    @Override
    public List<List<String>> getPermissionsForUser(String user) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getPermissionsForUser(user);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    @Override
    public boolean hasPermissionForUser(String user, String... permission) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    @Override
    public boolean hasPermissionForUser(String user, List<String> permission) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getUsersForRoleInDomain gets the users that has a role inside a domain.
     *
     * @param name   the user.
     * @param domain the domain.
     * @return the users for role in a domain.
     */
//    @Override
//    public List<String> getUsersForRoleInDomain(String name, String domain) {
//        try {
//            READ_WRITE_LOCK.readLock().lock();
//            return super.getUsersForRoleInDomain(name, domain);
//        } finally {
//            READ_WRITE_LOCK.readLock().unlock();
//        }
//    }

    /**
     * getRolesForUserInDomain gets the roles that a user has inside a domain.
     *
     * @param name   the user.
     * @param domain the domain.
     * @return the roles that the user has in the domain.
     */
    @Override
    public List<String> getRolesForUserInDomain(String name, String domain) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getRolesForUserInDomain(name, domain);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getPermissionsForUserInDomain gets permissions for a user or role inside a domain.
     *
     * @param user   the user.
     * @param domain the domain.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    @Override
    public List<List<String>> getPermissionsForUserInDomain(String user, String domain) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getPermissionsForUserInDomain(user, domain);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * addRoleForUserInDomain adds a role for a user inside a domain.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user   the user.
     * @param role   the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    @Override
    public boolean addRoleForUserInDomain(String user, String role, String domain) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addRoleForUserInDomain(user, role, domain);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRoleForUserInDomain deletes a role for a user inside a domain.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user   the user.
     * @param role   the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteRoleForUserInDomain(String user, String role, String domain) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteRoleForUserInDomain(user, role, domain);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
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
     * @param name   the user
     * @param domain the domain
     * @return implicit roles that a user has.
     */
    @Override
    public List<String> getImplicitRolesForUser(String name, String... domain) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getImplicitRolesForUser(name, domain);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
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
     * @param user the user.
     * @return implicit permissions for a user or role.
     */
    @Override
    public List<List<String>> getImplicitPermissionsForUser(String user) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getImplicitPermissionsForUser(user);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }
}
