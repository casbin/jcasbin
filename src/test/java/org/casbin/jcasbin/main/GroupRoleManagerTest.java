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

import org.casbin.jcasbin.rbac.GroupRoleManager;
import org.junit.Test;

import static org.casbin.jcasbin.main.TestUtil.testDomainEnforce;

public class GroupRoleManagerTest {
    @Test
    public void testGroupRoleManager() {
        Enforcer e = new Enforcer("examples/group_with_domain_model.conf", "examples/group_with_domain_policy.csv");
        e.setRoleManager(new GroupRoleManager(10));
        e.buildRoleLinks();

        testDomainEnforce(e, "alice", "domain1", "data1", "read", true);
    }

}
