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
import org.casbin.jcasbin.persist.BatchAdapter;
import org.casbin.jcasbin.persist.WatcherEx;
import org.casbin.jcasbin.util.Util;

import java.util.ArrayList;
import java.util.List;

/**
 * InternalEnforcer = CoreEnforcer + Internal API.
 */
class InternalEnforcer extends CoreEnforcer {
    /**
     * addPolicy adds a rule to the current policy.
     */
    boolean addPolicy(String sec, String ptype, List<String> rule) {
        if (model.hasPolicy(sec, ptype, rule)) {
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                adapter.addPolicy(sec, ptype, rule);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrintf("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        model.addPolicy(sec, ptype, rule);

        if (sec.equals("g")) {
            List<List<String>> rules = new ArrayList<>();
            rules.add(rule);
            buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_ADD, ptype, rules);
        }

        if (watcher != null && autoNotifyWatcher) {
            if (watcher instanceof WatcherEx) {
                ((WatcherEx) watcher).updateForAddPolicy(rule.toArray(new String[0]));
            } else {
                watcher.update();
            }
        }

        return true;
    }

    /**
     * addPolicies adds rules to the current policy.
     */
    boolean addPolicies(String sec, String ptype, List<List<String>> rules) {
        if (model.hasPolicies(sec, ptype, rules)) {
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                if (adapter instanceof BatchAdapter) {
                    ((BatchAdapter) adapter).addPolicies(sec, ptype, rules);
                }
            } catch (UnsupportedOperationException ignored) {
                Util.logPrintf("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        model.addPolicies(sec, ptype, rules);

        if (sec.equals("g")) {
            buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_ADD, ptype, rules);
        }

        if (watcher != null && autoNotifyWatcher) {
            watcher.update();
        }

        return true;
    }

    /**
     * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
     * @param op Policy operations.
     * @param ptype policy type.
     * @param rules the rules.
     */
    public void buildIncrementalRoleLinks(Model.PolicyOperations op, String ptype, List<List<String>> rules) {
        model.buildIncrementalRoleLinks(rm, op, "g", ptype, rules);
    }

    /**
     * removePolicy removes a rule from the current policy.
     */
    boolean removePolicy(String sec, String ptype, List<String> rule) {
        if (adapter != null && autoSave) {
            try {
                adapter.removePolicy(sec, ptype, rule);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrintf("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        boolean ruleRemoved = model.removePolicy(sec, ptype, rule);

        if (!ruleRemoved) {
            return false;
        }

        if (sec.equals("g")) {
            List<List<String>> rules = new ArrayList<>();
            rules.add(rule);
            buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_REMOVE, ptype, rules);
        }

        if (watcher != null && autoNotifyWatcher) {
            if (watcher instanceof WatcherEx) {
                ((WatcherEx) watcher).updateForRemovePolicy(rule.toArray(new String[0]));
            } else {
                watcher.update();
            }
        }

        return true;
    }

    /**
     * removePolicies removes rules from the current policy.
     */
    boolean removePolicies(String sec, String ptype, List<List<String>> rules) {
        if (model.hasPolicies(sec, ptype, rules)) {
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                if (adapter instanceof BatchAdapter) {
                    ((BatchAdapter) adapter).removePolicies(sec, ptype, rules);
                }
            } catch (UnsupportedOperationException ignored) {
                Util.logPrintf("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        boolean rulesRemoved = model.removePolicies(sec, ptype, rules);

        if (!rulesRemoved) {
            return false;
        }

        if (sec.equals("g")) {
            buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_REMOVE, ptype, rules);
        }

        if (watcher != null && autoNotifyWatcher) {
            // error intentionally ignored
            watcher.update();
        }

        return true;
    }

    /**
     * removeFilteredPolicy removes rules based on field filters from the current policy.
     */
    boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        if (fieldValues == null || fieldValues.length == 0) {
            Util.logPrint("Invaild fieldValues parameter");
            return false;
        }

        if (adapter != null && autoSave) {
            try {
                adapter.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrintf("Method not implemented");
            } catch (Exception e) {
                Util.logPrint("An exception occurred:" + e.getMessage());
                return false;
            }
        }

        List<List<String>> effects = model.removeFilteredPolicyReturnsEffects(sec, ptype, fieldIndex, fieldValues);
        boolean ruleRemoved = effects.size() > 0;

        if (!ruleRemoved) {
            return false;
        }

        if (sec.equals("g")) {
            buildIncrementalRoleLinks(Model.PolicyOperations.POLICY_REMOVE, ptype, effects);
        }

        if (watcher != null && autoNotifyWatcher) {
            // error intentionally ignored
            if (watcher instanceof WatcherEx) {
                ((WatcherEx) watcher).updateForRemoveFilteredPolicy(fieldIndex, fieldValues);
            } else {
                watcher.update();
            }
        }

        return true;
    }
}
