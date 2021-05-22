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

package org.casbin.jcasbin.main;

import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorObject;
import org.casbin.jcasbin.util.function.CustomFunction;
import org.junit.Test;

import java.util.Map;
import java.util.regex.Pattern;

import static org.casbin.jcasbin.main.TestUtil.testEnforce;

public class FunctionTest {

    @Test
    public void testCustomFunction() {
        Enforcer e = new Enforcer("examples/abac_rule_custom_function_model.conf", "examples/abac_rule_custom_function_policy.csv");

        // add a custom function
        CustomFunc customFunc = new CustomFunc();
        e.addFunction(customFunc.getName(), customFunc);

        testEnforce(e, new AbacAPIUnitTest.TestEvalRule("alice", 18), "/test/url1/url2/2", "GET", true);
        testEnforce(e, new AbacAPIUnitTest.TestEvalRule("alice", 18), "/test/2", "GET", false);
        testEnforce(e, new AbacAPIUnitTest.TestEvalRule("bob", 10), "/test/url1/url2/2", "GET", false);
    }

    public static class CustomFunc extends CustomFunction {
        @Override
        public AviatorObject call(Map<String, Object> env, AviatorObject arg1) {
            String obj = FunctionUtils.getStringValue(arg1, env);
            boolean res = Pattern.compile("/*/url1/url2/*", Pattern.CASE_INSENSITIVE).matcher(obj).find();
            return AviatorBoolean.valueOf(res);
        }

        @Override
        public String getName() {
            return "custom";
        }
    }
}
