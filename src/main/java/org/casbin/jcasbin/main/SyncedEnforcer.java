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
import java.util.function.Supplier;

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
    @Override
    public void setWatcher(Watcher watcher) {
        this.watcher = watcher;
        watcher.setUpdateCallback(this::loadPolicy);
    }

    /**
     * clearPolicy clears all policy.
     */
    @Override
    public void clearPolicy() {
        runSynchronized(super::clearPolicy);
    }

    /**
     * loadPolicy reloads the policy from file/database.
     */
    @Override
    public void loadPolicy() {
        runSynchronized(super::loadPolicy);
    }

    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    @Override
    public void loadFilteredPolicy(Object filter) {
        runSynchronized(() -> super.loadFilteredPolicy(filter));
    }

    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    @Override
    public void savePolicy() {
        runSynchronized(super::savePolicy);
    }

    /**
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
     */
    @Override
    public void buildRoleLinks() {
        runSynchronized(super::buildRoleLinks);
    }

    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    @Override
    public boolean enforce(Object... rvals) {
        return runSynchronized(() -> super.enforce(rvals));
    }

    /**
     * enforceWithMatcher use a custom matcher to decide whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "" or null.
     *
     * @param matcher the custom matcher.
     * @param rvals   the request needs to be mediated, usually an array
     *                of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    @Override
    public boolean enforceWithMatcher(String matcher, Object... rvals) {
        return runSynchronized(() -> super.enforceWithMatcher(matcher, rvals));
    }

    /**
     * batchEnforce enforce in batches
     *
     * @param rules the rules.
     * @return the results
     */
    @Override
    public List<Boolean> batchEnforce(List<List<String>> rules) {
        return runSynchronized(() -> super.batchEnforce(rules));
    }

    /**
     * batchEnforceWithMatcher enforce with matcher in batches
     *
     * @param matcher the custom matcher.
     * @param rules   the rules.
     * @return the results
     */
    @Override
    public List<Boolean> batchEnforceWithMatcher(String matcher, List<List<String>> rules) {
        return runSynchronized(() -> super.batchEnforceWithMatcher(matcher, rules));
    }

    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     *
     * @return all the subjects in "p" policy rules. It actually collects the
     *         0-index elements of "p" policy rules. So make sure your subject
     *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
     */
    @Override
    public List<String> getAllSubjects() {
        return runSynchronized(super::getAllSubjects);
    }

    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     *
     * @return all the objects in "p" policy rules. It actually collects the
     *         1-index elements of "p" policy rules. So make sure your object
     *         is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    @Override
    public List<String> getAllObjects() {
        return runSynchronized(super::getAllObjects);
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
    @Override
    public List<String> getAllNamedObjects(String ptype) {
        return runSynchronized(() -> super.getAllNamedObjects(ptype));
    }

    /**
     * getAllActions gets the list of actions that show up in the current policy.
     *
     * @return all the actions in "p" policy rules. It actually collects
     *         the 2-index elements of "p" policy rules. So make sure your action
     *         is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    @Override
    public List<String> getAllActions() {
        return runSynchronized(super::getAllActions);
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
    @Override
    public List<String> getAllNamedActions(String ptype) {
        return runSynchronized(() -> super.getAllNamedActions(ptype));
    }

    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     *
     * @return all the roles in "g" policy rules. It actually collects
     *         the 1-index elements of "g" policy rules. So make sure your
     *         role is the 1-index element, like (sub, role).
     *         Duplicates are removed.
     */
    @Override
    public List<String> getAllRoles() {
        return runSynchronized(super::getAllRoles);
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
    @Override
    public List<String> getAllNamedRoles(String ptype) {
        return runSynchronized(() -> super.getAllNamedRoles(ptype));
    }

    /**
     * getPolicy gets all the authorization rules in the policy.
     *
     * @return all the "p" policy rules.
     */
    @Override
    public List<List<String>> getPolicy() {
        return runSynchronized(super::getPolicy);
    }

    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules.
     */
    @Override
    public List<List<String>> getFilteredPolicy(int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.getFilteredPolicy(fieldIndex, fieldValues));
    }

    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return the "p" policy rules of the specified ptype.
     */
    @Override
    public List<List<String>> getNamedPolicy(String ptype) {
        return runSynchronized(() -> super.getNamedPolicy(ptype));
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
    @Override
    public List<List<String>> getFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.getFilteredNamedPolicy(ptype, fieldIndex, fieldValues));
    }

    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @return all the "g" policy rules.
     */
    @Override
    public List<List<String>> getGroupingPolicy() {
        return runSynchronized(super::getGroupingPolicy);
    }

    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @return the roles that the user has.
     */
    @Override
    public List<String> getRolesForUser(String name) {
        return runSynchronized(() -> super.getRolesForUser(name));
    }

    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
                          means not to match this field.
     * @return the filtered "g" policy rules.
     */
    @Override
    public List<List<String>> getFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.getFilteredGroupingPolicy(fieldIndex, fieldValues));
    }

    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return the "g" policy rules of the specified ptype.
     */
    @Override
    public List<List<String>> getNamedGroupingPolicy(String ptype) {
        return runSynchronized(() -> super.getNamedGroupingPolicy(ptype));
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
    @Override
    public List<List<String>> getFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.getFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues));
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasPolicy(List<String> params) {
        return runSynchronized(() -> super.hasPolicy(params));
    }

    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasPolicy(String... params) {
        return runSynchronized(() -> super.hasPolicy(params));
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasNamedPolicy(String ptype, List<String> params) {
        return runSynchronized(() -> super.hasNamedPolicy(ptype, params));
    }

    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasNamedPolicy(String ptype, String... params) {
        return runSynchronized(() -> super.hasNamedPolicy(ptype, params));
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addPolicy(List<String> params) {
        return runSynchronized(() -> super.addPolicy(params));
    }


    /**
     * addPolicies adds authorization rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding rule by adding the new rule.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addPolicies(List<List<String>> rules) {
        return runSynchronized(() -> super.addPolicies(rules));
    }

    /**
     * updatePolicy update an authorization rule to the current policy.
     *
     * @param params1 the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    @Override
    public boolean updatePolicy(List<String> params1, List<String> params2) {
        return runSynchronized(() -> super.updatePolicy(params1, params2));
    }

    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addPolicy(String... params) {
        return runSynchronized(() -> super.addPolicy(params));
    }

    /**
     * addPolicies adds authorization rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding rule by adding the new rule.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addPolicies(String[][] rules) {
        return runSynchronized(() -> super.addPolicies(rules));
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
    @Override
    public boolean addNamedPolicy(String ptype, List<String> params) {
        return runSynchronized(() -> super.addNamedPolicy(ptype, params));
    }

    /**
     * addNamedPolicies adds authorization rules to the current named policy.
     * If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    @Override
    public boolean addNamedPolicies(String ptype, List<List<String>> rules) {
        return runSynchronized(() -> super.addNamedPolicies(ptype, rules));
    }

    /**
     * updateNamedPolicy updates an authorization rule to the current named policy.
     *
     * @param ptype   the policy type, can be "p", "p2", "p3", ..
     * @param params1 the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    @Override
    public boolean updateNamedPolicy(String ptype, List<String> params1, List<String> params2) {
        return runSynchronized(() -> super.updateNamedPolicy(ptype, params1, params2));
    }

    /**
     * UpdateGroupingPolicy updates an authorization rule to the current named policy.
     *
     * @param params1 the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    @Override
    public boolean updateGroupingPolicy(List<String> params1, List<String> params2) {
        return runSynchronized(() -> super.updateGroupingPolicy(params1, params2));
    }

    /**
     * updateNamedGroupingPolicy updates an authorization rule to the current named policy.
     *
     * @param ptype   the policy type, can be "g", "g2", "g3", ..
     * @param params1 the old rule.
     * @param params2 the new rule.
     * @return succeeds or not.
     */
    @Override
    public boolean updateNamedGroupingPolicy(String ptype, List<String> params1, List<String> params2) {
        return runSynchronized(() -> super.updateNamedGroupingPolicy(ptype, params1, params2));
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
    @Override
    public boolean addNamedPolicy(String ptype, String... params) {
        return runSynchronized(() -> super.addNamedPolicy(ptype, params));
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removePolicy(List<String> params) {
        return runSynchronized(() -> super.removePolicy(params));
    }

    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removePolicy(String... params) {
        return runSynchronized(() -> super.removePolicy(params));
    }

    /**
     * removePolicies removes authorization rules from the current policy.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removePolicies(List<List<String>> rules) {
        return runSynchronized(() -> super.removePolicies(rules));
    }

    /**
     * removePolicies removes authorization rules from the current policy.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removePolicies(String[][] rules) {
        return runSynchronized(() -> super.removePolicies(rules));
    }

    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    @Override
    public boolean removeFilteredPolicy(int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.removeFilteredPolicy(fieldIndex, fieldValues));
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    @Override
    public boolean removeNamedPolicy(String ptype, List<String> params) {
        return runSynchronized(() -> super.removeNamedPolicy(ptype, params));
    }

    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    @Override
    public boolean removeNamedPolicy(String ptype, String... params) {
        return runSynchronized(() -> super.removeNamedPolicy(ptype, params));
    }

    /**
     * removeNamedPolicies removes authorization rules from the current named policy.
     *
     * @param ptype ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    @Override
    public boolean removeNamedPolicies(String ptype, List<List<String>> rules) {
        return runSynchronized(() -> super.removeNamedPolicies(ptype, rules));
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
    @Override
    public boolean removeFilteredNamedPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.removeFilteredNamedPolicy(ptype, fieldIndex, fieldValues));
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasGroupingPolicy(List<String> params) {
        return runSynchronized(() -> super.hasGroupingPolicy(params));
    }

    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasGroupingPolicy(String... params) {
        return runSynchronized(() -> super.hasGroupingPolicy(params));
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasNamedGroupingPolicy(String ptype, List<String> params) {
        return runSynchronized(() -> super.hasNamedGroupingPolicy(ptype, params));
    }

    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    @Override
    public boolean hasNamedGroupingPolicy(String ptype, String... params) {
        return runSynchronized(() -> super.hasNamedGroupingPolicy(ptype, params));
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addGroupingPolicy(List<String> params) {
        return runSynchronized(() -> super.addGroupingPolicy(params));
    }

    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addGroupingPolicy(String... params) {
        return runSynchronized(() -> super.addGroupingPolicy(params));
    }

    /**
     * addGroupingPolicies adds role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addGroupingPolicies(List<List<String>> rules) {
        return runSynchronized(() -> super.addGroupingPolicies(rules));
    }

    /**
     * addGroupingPolicies adds role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean addGroupingPolicies(String[][] rules) {
        return runSynchronized(() -> super.addGroupingPolicies(rules));
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
    @Override
    public boolean addNamedGroupingPolicy(String ptype, List<String> params) {
        return runSynchronized(() -> super.addNamedGroupingPolicy(ptype, params));
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
    @Override
    public boolean addNamedGroupingPolicy(String ptype, String... params) {
        return runSynchronized(() -> super.addNamedGroupingPolicy(ptype, params));
    }

    /**
     * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    @Override
    public boolean addNamedGroupingPolicies(String ptype, List<List<String>> rules) {
        return runSynchronized(() -> super.addNamedGroupingPolicies(ptype, rules));
    }

    /**
     * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
     * If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
     * Otherwise the function returns true for the corresponding policy rule by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    @Override
    public boolean addNamedGroupingPolicies(String ptype, String[][] rules) {
        return runSynchronized(() -> super.addNamedGroupingPolicies(ptype, rules));
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removeGroupingPolicy(List<String> params) {
        return runSynchronized(() -> super.removeGroupingPolicy(params));
    }

    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removeGroupingPolicy(String... params) {
        return runSynchronized(() -> super.removeGroupingPolicy(params));
    }

    /**
     * removeGroupingPolicies removes role inheritance rules from the current policy.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removeGroupingPolicies(List<List<String>> rules) {
        return runSynchronized(() -> super.removeGroupingPolicies(rules));
    }

    /**
     * removeGroupingPolicies removes role inheritance rules from the current policy.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    @Override
    public boolean removeGroupingPolicies(String[][] rules) {
        return runSynchronized(() -> super.removeGroupingPolicies(rules));
    }

    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    @Override
    public boolean removeFilteredGroupingPolicy(int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.removeFilteredGroupingPolicy(fieldIndex, fieldValues));
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    @Override
    public boolean removeNamedGroupingPolicy(String ptype, List<String> params) {
        return runSynchronized(() -> super.removeNamedGroupingPolicy(ptype, params));
    }

    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    @Override
    public boolean removeNamedGroupingPolicy(String ptype, String... params) {
        return runSynchronized(() -> super.removeNamedGroupingPolicy(ptype, params));
    }

    /**
     * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    @Override
    public boolean removeNamedGroupingPolicies(String ptype, List<List<String>> rules) {
        return runSynchronized(() -> super.removeNamedGroupingPolicies(ptype, rules));
    }

    /**
     * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    @Override
    public boolean removeNamedGroupingPolicies(String ptype, String[][] rules) {
        return runSynchronized(() -> super.removeNamedGroupingPolicies(ptype, rules));
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
    @Override
    public boolean removeFilteredNamedGroupingPolicy(String ptype, int fieldIndex, String... fieldValues) {
        return runSynchronized(() -> super.removeFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues));
    }

    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @return the users that has the role.
     */
    @Override
    public List<String> getUsersForRole(String name) {
        return runSynchronized(() -> super.getUsersForRole(name));
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
        return runSynchronized(() -> super.hasRoleForUser(name, role));
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
        return runSynchronized(() -> super.addRoleForUser(user, role));
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
        return runSynchronized(() -> super.deleteRoleForUser(user, role));
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
        return runSynchronized(() -> super.deleteRolesForUser(user));
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
        return runSynchronized(() -> super.deleteUser(user));
    }

    /**
     * deleteRole deletes a role.
     *
     * @param role the role.
     */
    @Override
    public void deleteRole(String role) {
        runSynchronized(() -> super.deleteRole(role));
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
        return runSynchronized(() -> super.deletePermission(permission));
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
        return runSynchronized(() -> super.deletePermission(permission));
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
        return runSynchronized(() -> super.addPermissionForUser(user, permission));
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
        return runSynchronized(() -> super.addPermissionForUser(user, permission));
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
        return runSynchronized(() -> super.deletePermissionForUser(user, permission));
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
        return runSynchronized(() -> super.deletePermissionForUser(user, permission));
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
        return runSynchronized(() -> super.deletePermissionsForUser(user));
    }

    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user   the user.
     * @param domain the user's domain.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    @Override
    public List<List<String>> getPermissionsForUser(String user, String... domain) {
        return runSynchronized(() -> super.getPermissionsForUser(user, domain));
    }

    /**
     * GetNamedPermissionsForUser gets permissions for a user or role by named policy.
     *
     * @param pType  the name policy.
     * @param user   the user.
     * @param domain domain.
     * @return the permissions.
     */
    @Override
    public List<List<String>> getNamedPermissionsForUser(String pType, String user, String... domain) {
        return runSynchronized(() -> super.getNamedPermissionsForUser(pType, user, domain));
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
        return runSynchronized(() -> super.hasPermissionForUser(user, permission));
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
        return runSynchronized(() -> super.hasPermissionForUser(user, permission));
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
        return runSynchronized(() -> super.getRolesForUserInDomain(name, domain));
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
        return runSynchronized(() -> super.getPermissionsForUserInDomain(user, domain));
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
        return runSynchronized(() -> super.addRoleForUserInDomain(user, role, domain));
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
        return runSynchronized(() -> super.deleteRoleForUserInDomain(user, role, domain));
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
        return runSynchronized(() -> super.getImplicitRolesForUser(name, domain));
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
    @Override
    public List<List<String>> getImplicitPermissionsForUser(String user, String... domain) {
        return runSynchronized(() -> super.getImplicitPermissionsForUser(user, domain));
    }

    /**
     * GetNamedImplicitPermissionsForUser gets implicit permissions for a user or role by named policy.
     * Compared to GetNamedPermissionsForUser(), this function retrieves permissions for inherited roles.
     * For example:
     * p, admin, data1, read
     * p2, admin, create
     * g, alice, admin
     * <p>
     * GetImplicitPermissionsForUser("alice") can only get: [["admin", "data1", "read"]], whose policy is default policy "p"
     * But you can specify the named policy "p2" to get: [["admin", "create"]] by GetNamedImplicitPermissionsForUser("p2","alice")
     *
     * @param pType     the name policy.
     * @param user      the user.
     * @param domain    the user's domain.
     * @return implicit permissions for a user or role by named policy.
     */
    @Override
    public List<List<String>> getNamedImplicitPermissionsForUser(String pType, String user, String... domain) {
        return runSynchronized(() -> super.getNamedImplicitPermissionsForUser(pType, user, domain));
    }

    private <T> T runSynchronized(Supplier<T> action) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return action.get();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    private void runSynchronized(Runnable action) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            action.run();
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }
}
