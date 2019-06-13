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

package org.casbin.jcasbin.rbac;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * GroupRoleManager is used for authorization if the user's group is the role who has permission,
 * but the group information is in the default format (policy start with "g") and the role information
 * is in named format (policy start with "g2", "g3", ...).
 * e.g.
 * p, admin, domain1, data1, read
 * g, alice, group1
 * g2, group1, admin, domain1
 *
 * As for the previous example, alice should have the permission to read data1, but if we use the
 * DefaultRoleManager, it will return false.
 * GroupRoleManager is to handle this situation.
 */
public class GroupRoleManager extends DefaultRoleManager {
    /**
     * GroupRoleManager is the constructor for creating an instance of the
     * GroupRoleManager implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     */
    public GroupRoleManager(int maxHierarchyLevel) {
        super(maxHierarchyLevel);
    }

    /**
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    @Override
    public boolean hasLink(String name1, String name2, String... domain) {
        if(super.hasLink(name1, name2, domain)) {
            return true;
        }
        // check name1's groups
        if (domain.length == 1) {
            try {
                List<String> groups = Optional.ofNullable(super.getRoles(name1)).orElse(new ArrayList<>());
                for(String group : groups) {
                    if(hasLink(group, name2, domain)) {
                        return true;
                    }
                }
            } catch (IllegalArgumentException ignore) {
                return false;
            }
        }
        return false;
    }
}
