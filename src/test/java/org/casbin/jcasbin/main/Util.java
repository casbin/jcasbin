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

package org.casbin.jcasbin.main;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class Util {
    static void testEnforce(Enforcer e, String sub, Object obj, String act, boolean res) {
        assertEquals(res, e.enforce(sub, obj, act));
    }

    static void testEnforceWithoutUsers(Enforcer e, String obj, String act, boolean res) {
        assertEquals(res, e.enforce(obj, act));
    }

    static void testDomainEnforce(Enforcer e, String sub, String dom, String obj, String act, boolean res) {
        assertEquals(res, e.enforce(sub, dom, obj, act));
    }

    static void testGetPolicy(Enforcer e, List res) {
        List myRes = e.getPolicy();
        org.casbin.jcasbin.util.Util.logPrint("Policy: " + myRes);

        if (!org.casbin.jcasbin.util.Util.array2DEquals(res, myRes)) {
            fail("Policy: " + myRes + ", supposed to be " + res);
        }
    }
}
