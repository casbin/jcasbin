// Copyright 2020 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.util.function;

import com.googlecode.aviator.AviatorEvaluatorInstance;
import com.googlecode.aviator.runtime.function.AbstractFunction;

import java.util.Map;

/**
 * @author: shink
 */
public abstract class CustomFunction extends AbstractFunction {

    private AviatorEvaluatorInstance aviatorEval;

    public String replaceTargets(String exp, Map<String, Object> env) {
        for (String key : env.keySet()) {
            int index;
            if ((index = key.indexOf('_')) != -1) {
                String s = key.substring(index + 1);
                exp = exp.replace("." + s, "_" + s);
            }
        }
        return exp;
    }

    public AviatorEvaluatorInstance getAviatorEval() {
        return aviatorEval;
    }

    public void setAviatorEval(AviatorEvaluatorInstance aviatorEval) {
        this.aviatorEval = aviatorEval;
    }
}
