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

package org.casbin.jcasbin.util.function;

import com.googlecode.aviator.runtime.function.AbstractFunction;
import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorObject;
import org.casbin.jcasbin.util.BuiltInFunctions;

import java.util.Map;

/**
 * IPMatchFunc is the wrapper for ipMatch.
 */
public class IPMatchFunc extends AbstractFunction {
    @Override
    public AviatorObject call(Map<String, Object> env, AviatorObject arg1, AviatorObject arg2) {
        String ip1 = FunctionUtils.getStringValue(arg1, env);
        String ip2 = FunctionUtils.getStringValue(arg2, env);

        return AviatorBoolean.valueOf(BuiltInFunctions.ipMatch(ip1, ip2));
    }

    @Override
    public String getName() {
        return "ipMatch";
    }
}
