// Copyright 2022 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

/**
 * @author Yixiang Zhao (@seriouszyx)
 **/
public class RoleManagerUnitTest {
    @Test
    public void testRole() {
        RoleManager rm = new DefaultRoleManager(3);
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("u3", "g2");
        rm.addLink("u4", "g2");
        rm.addLink("u4", "g3");
        rm.addLink("g1", "g3");

        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", true);
        TestUtil.testHasRole(rm, "u1", "g2", false);
        TestUtil.testHasRole(rm, "u1", "g3", true);
        TestUtil.testHasRole(rm, "u2", "g1", true);
        TestUtil.testHasRole(rm, "u2", "g2", false);
        TestUtil.testHasRole(rm, "u2", "g3", true);
        TestUtil.testHasRole(rm, "u3", "g1", false);
        TestUtil.testHasRole(rm, "u3", "g2", true);
        TestUtil.testHasRole(rm, "u3", "g3", false);
        TestUtil.testHasRole(rm, "u4", "g1", false);
        TestUtil.testHasRole(rm, "u4", "g2", true);
        TestUtil.testHasRole(rm, "u4", "g3", true);

        TestUtil.testGetRoles(rm, "u1", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u2", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u3", Collections.singletonList("g2"));
        TestUtil.testGetRoles(rm, "u4", Arrays.asList("g2", "g3"));
        TestUtil.testGetRoles(rm, "g1", Collections.singletonList("g3"));
        TestUtil.testGetRoles(rm, "g2", Collections.emptyList());
        TestUtil.testGetRoles(rm, "g3", Collections.emptyList());

        rm.deleteLink("g1", "g3");
        rm.deleteLink("u4", "g2");

        // Current role inheritance tree after deleting the links:
        //             g3    g2
        //               \     \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", true);
        TestUtil.testHasRole(rm, "u1", "g2", false);
        TestUtil.testHasRole(rm, "u1", "g3", false);
        TestUtil.testHasRole(rm, "u2", "g1", true);
        TestUtil.testHasRole(rm, "u2", "g2", false);
        TestUtil.testHasRole(rm, "u2", "g3", false);
        TestUtil.testHasRole(rm, "u3", "g1", false);
        TestUtil.testHasRole(rm, "u3", "g2", true);
        TestUtil.testHasRole(rm, "u3", "g3", false);
        TestUtil.testHasRole(rm, "u4", "g1", false);
        TestUtil.testHasRole(rm, "u4", "g2", false);
        TestUtil.testHasRole(rm, "u4", "g3", true);

        TestUtil.testGetRoles(rm, "u1", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u2", Collections.singletonList("g1"));
        TestUtil.testGetRoles(rm, "u3", Collections.singletonList("g2"));
        TestUtil.testGetRoles(rm, "u4", Collections.singletonList("g3"));
        TestUtil.testGetRoles(rm, "g1", Collections.emptyList());
        TestUtil.testGetRoles(rm, "g2", Collections.emptyList());
        TestUtil.testGetRoles(rm, "g3", Collections.emptyList());
    }

    @Test
    public void testDomainRole() {
        RoleManager rm = new DefaultRoleManager(3);
        rm.addLink("u1", "g1", "domain1");
        rm.addLink("u2", "g1", "domain1");
        rm.addLink("u3", "admin", "domain2");
        rm.addLink("u4", "admin", "domain2");
        rm.addLink("u4", "admin", "domain1");
        rm.addLink("g1", "admin", "domain1");

        //  Current role inheritance tree:
        //  domain1:admin    domain2:admin
        //      /       \  /       \
        //  domain1:g1     u4         u3
        //      /  \
        //  u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u1", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u1", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u1", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u2", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u2", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u2", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u2", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u3", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain2", true);

        TestUtil.testHasRole(rm, "u4", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u4", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u4", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u4", "admin", "domain2", true);

        rm.deleteLink("g1", "admin", "domain1");
        rm.deleteLink("u4", "admin", "domain2");

        // Current role inheritance tree after deleting the links:
        //       domain1:admin    domain2:admin
        //                    \          \
        //      domain1:g1     u4         u3
        //         /  \
        //       u1    u2

        TestUtil.testHasRole(rm, "u1", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u1", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u1", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u1", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u2", "g1", "domain1", true);
        TestUtil.testHasRole(rm, "u2", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u2", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u2", "admin", "domain2", false);

        TestUtil.testHasRole(rm, "u3", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain1", false);
        TestUtil.testHasRole(rm, "u3", "admin", "domain2", true);

        TestUtil.testHasRole(rm, "u4", "g1", "domain1", false);
        TestUtil.testHasRole(rm, "u4", "g1", "domain2", false);
        TestUtil.testHasRole(rm, "u4", "admin", "domain1", true);
        TestUtil.testHasRole(rm, "u4", "admin", "domain2", false);
    }

    @Test
    public void testClear() {
        RoleManager rm = new DefaultRoleManager(3);
        rm.addLink("u1", "g1");
        rm.addLink("u2", "g1");
        rm.addLink("u3", "g2");
        rm.addLink("u4", "g2");
        rm.addLink("u4", "g3");
        rm.addLink("g1", "g3");

        // Current role inheritance tree:
        //             g3    g2
        //            /  \  /  \
        //          g1    u4    u3
        //         /  \
        //       u1    u2

        rm.clear();

        // All data is cleared.
        // No role inheritance now.

        TestUtil.testHasRole(rm, "u1", "g1", false);
        TestUtil.testHasRole(rm, "u1", "g2", false);
        TestUtil.testHasRole(rm, "u1", "g3", false);
        TestUtil.testHasRole(rm, "u2", "g1", false);
        TestUtil.testHasRole(rm, "u2", "g2", false);
        TestUtil.testHasRole(rm, "u2", "g3", false);
        TestUtil.testHasRole(rm, "u3", "g1", false);
        TestUtil.testHasRole(rm, "u3", "g2", false);
        TestUtil.testHasRole(rm, "u3", "g3", false);
        TestUtil.testHasRole(rm, "u4", "g1", false);
        TestUtil.testHasRole(rm, "u4", "g2", false);
        TestUtil.testHasRole(rm, "u4", "g3", false);
    }
}
