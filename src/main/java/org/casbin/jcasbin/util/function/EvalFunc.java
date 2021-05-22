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

import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorObject;
import org.casbin.jcasbin.util.BuiltInFunctions;

import java.util.Map;

/**
 * EvalFunc is the wrapper for eval.
 * It extends CustomFunction, so it can be used in matcher and policy rule.
 *
 * @author shink
 */
public class EvalFunc extends CustomFunction {

    @Override
    public AviatorObject call(Map<String, Object> env, AviatorObject arg1) {
        String eval = FunctionUtils.getStringValue(arg1, env);
        eval = replaceTargets(eval, env);
        return AviatorBoolean.valueOf(BuiltInFunctions.eval(eval, env, getAviatorEval()));
    }

    @Override
    public String getName() {
        return "eval";
    }
}
