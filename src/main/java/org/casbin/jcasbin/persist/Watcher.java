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

package org.casbin.jcasbin.persist;

import java.util.function.Consumer;

/**
 * Watcher is the interface for Casbin watchers.
 */
public interface Watcher {
    /**
     * SetUpdateCallback sets the callback function that the watcher will call
     * when the policy in DB has been changed by other instances.
     * A classic callback is Enforcer.loadPolicy().
     *
     * @param runnable the callback function, will be called when policy is updated.
     */
    void setUpdateCallback(Runnable runnable);

    /**
     * SetUpdateCallback sets the callback function that the watcher will call
     * when the policy in DB has been changed by other instances.
     * A classic callback is Enforcer.loadPolicy().
     *
     * @param func the callback function, will be called when policy is updated.
     */
    void setUpdateCallback(Consumer<String> func);

    /**
     * Update calls the update callback of other instances to synchronize their policy.
     * It is usually called after changing the policy in DB, like Enforcer.savePolicy(),
     * Enforcer.addPolicy(), Enforcer.removePolicy(), etc.
     */
    void update();
}
