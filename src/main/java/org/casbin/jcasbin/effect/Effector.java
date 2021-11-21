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

package org.casbin.jcasbin.effect;

/**
 * Effector is the interface for Casbin effectors.
 */
public interface Effector {
    /**
     * mergeEffects merges all matching results collected by the enforcer into a single decision.
     *
     * @param expr the expression of [policy_effect].
     * @param effects the effects of all matched rules.
     * @param results the matcher results of all matched rules.
     * @return the final effect.
     *
     * @deprecated use newStreamEffector instead of this.
     */
    boolean mergeEffects(String expr, Effect[] effects, float[] results);

    default StreamEffector newStreamEffector(String expr) {
       throw new UnsupportedOperationException("Not implemented");
    }
}
