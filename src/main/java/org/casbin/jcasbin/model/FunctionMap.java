// Copyright 2017 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.model;

import com.googlecode.aviator.AviatorEvaluatorInstance;
import com.googlecode.aviator.runtime.type.AviatorFunction;
import org.casbin.jcasbin.util.function.*;

import java.util.HashMap;
import java.util.Map;

/**
 * FunctionMap represents the collection of Function.
 */
public class FunctionMap {
    /**
     * AviatorFunction represents a function that is used in the matchers, used to get attributes in ABAC.
     */
    public Map<String, AviatorFunction> fm;

    public boolean isModify = false;

    /**
     * addFunction adds an expression function.
     *
     * @param name the name of the new function.
     * @param function the function.
     */
    public void addFunction(String name, AviatorFunction function) {
        fm.put(name, function);
        isModify=true;
    }

    /**
     * setAviatorEval adds AviatorEvaluatorInstance to the custom function.
     *
     * @param name        the name of the custom function.
     * @param aviatorEval the AviatorEvaluatorInstance object.
     */
    public void setAviatorEval(String name, AviatorEvaluatorInstance aviatorEval) {
        if (fm.containsKey(name) && fm.get(name) instanceof CustomFunction) {
            ((CustomFunction) fm.get(name)).setAviatorEval(aviatorEval);
        }
    }

    /**
     * setAviatorEval adds AviatorEvaluatorInstance to all the custom function.
     *
     * @param aviatorEval the AviatorEvaluatorInstance object.
     */
    public void setAviatorEval(AviatorEvaluatorInstance aviatorEval) {
        for (AviatorFunction function : fm.values()) {
            if (function instanceof CustomFunction) {
                ((CustomFunction) function).setAviatorEval(aviatorEval);
            }
        }
    }

    /**
     * loadFunctionMap loads an initial function map.
     *
     * @return the constructor of FunctionMap.
     */
    public static FunctionMap loadFunctionMap() {
        FunctionMap fm = new FunctionMap();
        fm.fm = new HashMap<>();

        fm.addFunction("keyMatch", new KeyMatchFunc());
        fm.addFunction("keyMatch2", new KeyMatch2Func());
        fm.addFunction("keyMatch3", new KeyMatch3Func());
        fm.addFunction("keyMatch4", new KeyMatch4Func());
        fm.addFunction("keyMatch5", new KeyMatch5Func());
        fm.addFunction("keyGet", new KeyGetFunc());
        fm.addFunction("keyGet2", new KeyGet2Func());
        fm.addFunction("regexMatch", new RegexMatchFunc());
        fm.addFunction("ipMatch", new IPMatchFunc());
        fm.addFunction("eval", new EvalFunc());
        fm.addFunction("globMatch", new GlobMatchFunc());

        return fm;
    }
}
