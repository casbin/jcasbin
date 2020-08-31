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

import java.util.List;

public interface RoleManager {
    /**
     * Clear clears all stored data and resets the role manager to the initial state.
     */
    void clear();

    /**
     * addLink adds the inheritance link between two roles. role: name1 and role: name2. domain is a
     * prefix to the roles.
     *
     * @param name1 the first role (or user).
     * @param name2 the second role.
     * @param domain the domain the roles belong to.
     */
    void addLink(String name1, String name2, String... domain);

    /**
     * deleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
     * domain is a prefix to the roles.
     *
     * @param name1 the first role (or user).
     * @param name2 the second role.
     * @param domain the domain the roles belong to.
     */
    void deleteLink(String name1, String name2, String... domain);

    /**
     * hasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param name1 the first role (or a user).
     * @param name2 the second role.
     * @param domain the domain the roles belong to.
     * @return whether name1 inherits name2 (name1 has role name2).
     */
    boolean hasLink(String name1, String name2, String... domain);

    /**
     * getRoles gets the roles that a user inherits. domain is a prefix to the roles.
     *
     * @param name the user (or a role).
     * @param domain the domain the roles belong to.
     * @return the roles.
     */
    List<String> getRoles(String name, String... domain);

    /**
     * getUsers gets the users that inherits a role.
     * 
     * @param name the role.
     * @param domain is a prefix to the users (can be used for other purposes).
     * @return the users.
     */
    List<String> getUsers(String name, String... domain);

    /**
     * printRoles prints all the roles to log.
     */
    void printRoles();
}
