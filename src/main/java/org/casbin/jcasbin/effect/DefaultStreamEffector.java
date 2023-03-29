// Copyright 2021 The casbin Authors. All Rights Reserved.
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

public class DefaultStreamEffector implements StreamEffector {
    private final String expr;
    private boolean done = false;
    private boolean effect = false;
    private int explainIndex = -1;

    public DefaultStreamEffector(String expr) {
        this.expr = expr;
    }

    @Override
    public StreamEffectorResult current() {
        return new DefaultStreamEffectorResult(effect, done, explainIndex);
    }

    @Override
    public boolean push(Effect eft, int currentIndex, int policySize) {
        switch (this.expr) {
            case "some(where (p_eft == allow))":
                if (eft == Effect.Allow) {
                    this.effect = true;
                    explainIndex = currentIndex;
                    this.done = true;
                }
                break;
            case "!some(where (p_eft == deny))":
                this.effect = true;
                if (eft == Effect.Deny) {
                    this.effect = false;
                    explainIndex = currentIndex;
                    this.done = true;
                }
                break;
            case "some(where (p_eft == allow)) && !some(where (p_eft == deny))":
                if (eft == Effect.Allow) {
                    this.effect = true;
                    explainIndex = explainIndex == -1 ? currentIndex : explainIndex;
                } else if (eft == Effect.Deny) {
                    this.effect = false;
                    explainIndex = currentIndex;
                    this.done = true;
                }
                break;
            case "priority(p_eft) || deny":
            case "subjectPriority(p_eft) || deny":
                if (eft != Effect.Indeterminate) {
                    this.effect = eft == Effect.Allow;
                    explainIndex = currentIndex;
                    this.done = true;
                }
                break;
            default:
                throw new UnsupportedOperationException("unsupported effect");
        }

        return this.done;
    }
}
