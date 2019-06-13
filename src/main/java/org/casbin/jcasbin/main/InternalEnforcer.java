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

import org.casbin.jcasbin.util.Util;

import java.util.List;

/**
 * InternalEnforcer = CoreEnforcer + Internal API.
 */
class InternalEnforcer extends CoreEnforcer {
    /**
     * addPolicy adds a rule to the current policy.
     */
    boolean addPolicy(String sec, String ptype, List<String> rule) {

        if (adapter != null && autoSave) {
            try {
                adapter.addPolicy(sec, ptype, rule);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrintf("Method not implemented");
            }

            if (watcher != null) {
                // error intentionally ignored
                watcher.update();
            }
        }

        return model.addPolicy(sec, ptype, rule);
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
            }

            if (watcher != null) {
                // error intentionally ignored
                watcher.update();
            }
        }

        return  model.removePolicy(sec, ptype, rule);
    }

    /**
     * removeFilteredPolicy removes rules based on field filters from the current policy.
     */
    boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {

        if (adapter != null && autoSave) {
            try {
                adapter.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
            } catch (UnsupportedOperationException ignored) {
                Util.logPrintf("Method not implemented");
            }

            if (watcher != null) {
                // error intentionally ignored
                watcher.update();
            }
        }

        return model.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
    }
}
