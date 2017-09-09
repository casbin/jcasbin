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
     * addLink adds the inheritance link between two roles. role: name1 and role: name2.
     * domain is a prefix to the roles.
     */
    public void addLink(String name1, String name2, String... domain);

    /**
     * deleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
     * domain is a prefix to the roles.
     */
    public void deleteLink(String name1, String name2, String... domain);

    /**
     * hasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    public boolean hasLink(String name1, String name2, String... domain);

    /**
     * getRoles gets the roles that a user inherits.
     * domain is a prefix to the roles.
     */
    public List<String> getRoles(String name, String... domain);

    /**
     * getUsers gets the users that inherits a role.
     */
    public List<String> getUsers(String name);

    /**
     * printRoles prints all the roles to log.
     */
    public void printRoles();
}
