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

import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;

import java.util.List;

/**
 * Assertion represents an expression in a section of the model.
 * For example: r = sub, obj, act
 */
public class Assertion {
    private String key;
    private String value;
    private List<String> tokens;
    private List<List<String>> policy;
    private RoleManager rm;

    protected void buildRoleLinks(RoleManager rm) throws Exception {
        this.rm = rm;
        int count = 0;
        for (int i = 0; i < this.value.length(); i ++) {
            if (this.value.charAt(i) == '_') {
                count ++;
            }
        }
        for (List<String> rule : this.policy) {
            if (count < 2) {
                throw new Exception("the number of \"_\" in role definition should be at least 2");
            }
            if (rule.size() < count) {
                throw new Exception("grouping policy elements do not meet role definition");
            }

            if (count == 2) {
                this.rm.addLink(rule.get(0), rule.get(1));
            } else if (count == 3) {
                this.rm.addLink(rule.get(0), rule.get(1), rule.get(2));
            } else if (count == 4) {
                this.rm.addLink(rule.get(0), rule.get(1), rule.get(2), rule.get(3));
            }
        }

        Util.logPrint("Role links for: " + this.key);
        this.rm.printRoles();
    }
}
