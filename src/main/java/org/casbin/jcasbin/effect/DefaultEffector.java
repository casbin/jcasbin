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
 * DefaultEffector is default effector for Casbin.
 */
public class DefaultEffector implements Effector {
    /**
     * DefaultEffector is the constructor for DefaultEffector.
     */
    public DefaultEffector() {
    }

    /**
     * mergeEffects merges all matching results collected by the enforcer into a single decision.
     */
    @Override
    public boolean mergeEffects(String expr, Effect[] effects, float[] results) {
        boolean result;
        if (expr.equals("some(where (p_eft == allow))")) {
            result = false;
            for (Effect eft : effects) {
                if (eft == Effect.Allow) {
                    result = true;
                    break;
                }
            }
        } else if (expr.equals("!some(where (p_eft == deny))")) {
            result = true;
            for (Effect eft : effects) {
                if (eft == Effect.Deny) {
                    result = false;
                    break;
                }
            }
        } else if (expr.equals("some(where (p_eft == allow)) && !some(where (p_eft == deny))")) {
            result = false;
            for (Effect eft : effects) {
                if (eft == Effect.Allow) {
                    result = true;
                } else if (eft == Effect.Deny) {
                    result = false;
                    break;
                }
            }
        } else if (expr.equals("priority(p_eft) || deny") || expr.equals("subjectPriority(p_eft) || deny")) {
            result = false;
            for (Effect eft : effects) {
                if (eft != Effect.Indeterminate) {
                    if (eft == Effect.Allow) {
                        result = true;
                    } else {
                        result = false;
                    }
                    break;
                }
            }
        } else {
            throw new UnsupportedOperationException("unsupported effect");
        }

        return result;
    }

    @Override
    public StreamEffector newStreamEffector(String expr) {
        return new DefaultStreamEffector(expr);
    }
}
