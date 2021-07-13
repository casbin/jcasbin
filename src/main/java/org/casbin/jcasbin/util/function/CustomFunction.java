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
        //Replace the first dot, because it can't be recognized by the 'reg' below.
        if (exp.startsWith( "r") || exp.startsWith( "p")) {
            exp = exp.replaceFirst("\\.","_");
        }
        //match example: "&&r.","||r."，"=r."
        String reg = "([| =)(&<>,+\\-*/!])((r|p)[0-9]*)\\.";
        exp = exp.replaceAll(reg,"$1$2_");
        return exp;
    }

    public AviatorEvaluatorInstance getAviatorEval() {
        return aviatorEval;
    }

    public void setAviatorEval(AviatorEvaluatorInstance aviatorEval) {
        this.aviatorEval = aviatorEval;
    }
}
