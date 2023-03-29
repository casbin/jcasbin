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

public class DefaultStreamEffectorResult implements StreamEffectorResult {
    private  boolean done;
    private  boolean effect;
    private int explainIndex;
    public DefaultStreamEffectorResult(){

}

    public DefaultStreamEffectorResult(boolean effect, boolean done, int explainIndex) {
        this.effect = effect;
        this.done = done;
        this.explainIndex = explainIndex;
    }

    @Override
    public boolean hasEffect() {
        return effect;
    }

    @Override
    public boolean isDone() {
        return done;
    }

    public void setEffect(boolean effect) {
        this.effect = effect;
    }

    public void setDone(boolean done) {
        this.done = done;
    }

    @Override
    public int getExplainIndex() {
        return explainIndex;
    }

    public void setExplainIndex(int explainIndex) {
        this.explainIndex = explainIndex;
    }
}
