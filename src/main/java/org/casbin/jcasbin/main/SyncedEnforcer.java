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

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;

import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * SyncedEnforcer = ManagementEnforcer + RBAC API.
 */
public class SyncedEnforcer extends Enforcer {

    private final static ReadWriteLock READ_WRITE_LOCK = new ReentrantReadWriteLock();

    /**
     * ;
     * SyncedEnforcer is the default constructor.
     */
    public SyncedEnforcer() {
        super();
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     */
    public SyncedEnforcer(String modelPath, String policyFile) {
        super(modelPath, policyFile);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a database adapter.
     *
     * @param modelPath the path of the model file.
     * @param adapter   the adapter.
     */
    public SyncedEnforcer(String modelPath, Adapter adapter) {
        super(modelPath, adapter);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m       the model.
     * @param adapter the adapter.
     */
    public SyncedEnforcer(Model m, Adapter adapter) {
        super(m, adapter);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    public SyncedEnforcer(Model m) {
        super(m);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model file.
     *
     * @param modelPath the path of the model file.
     */
    public SyncedEnforcer(String modelPath) {
        super(modelPath);
    }

    /**
     * SyncedEnforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     * @param enableLog  whether to enable Casbin's log.
     */
    public SyncedEnforcer(String modelPath, String policyFile, boolean enableLog) {
        super(modelPath, policyFile, enableLog);
    }

    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @return the roles that the user has.
     */
    @Override
    public List<String> getRolesForUser(String name) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getRolesForUser(name);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @return the users that has the role.
     */
    @Override
    public List<String> getUsersForRole(String name) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getUsersForRole(name);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasRoleForUser determines whether a user has a role.
     *
     * @param name the user.
     * @param role the role.
     * @return whether the user has the role.
     */
    @Override
    public boolean hasRoleForUser(String name, String role) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasRoleForUser(name, role);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * addRoleForUser adds a role for a user.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    @Override
    public boolean addRoleForUser(String user, String role) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addRoleForUser(user, role);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteRoleForUser(String user, String role) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteRoleForUser(user, role);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteRolesForUser(String user) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteRolesForUser(user);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteUser(String user) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteUser(user);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRole deletes a role.
     *
     * @param role the role.
     */
    @Override
    public void deleteRole(String role) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            super.deleteRole(role);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermission(String... permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermission(permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermission(List<String> permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermission(permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean addPermissionForUser(String user, String... permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean addPermissionForUser(String user, List<String> permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermissionForUser(String user, String... permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermissionForUser(String user, List<String> permission) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    @Override
    public boolean deletePermissionsForUser(String user) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deletePermissionsForUser(user);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user the user.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    @Override
    public List<List<String>> getPermissionsForUser(String user) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getPermissionsForUser(user);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    @Override
    public boolean hasPermissionForUser(String user, String... permission) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user       the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    @Override
    public boolean hasPermissionForUser(String user, List<String> permission) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.hasPermissionForUser(user, permission);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getRolesForUserInDomain gets the roles that a user has inside a domain.
     *
     * @param name   the user.
     * @param domain the domain.
     * @return the roles that the user has in the domain.
     */
    @Override
    public List<String> getRolesForUserInDomain(String name, String domain) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getRolesForUserInDomain(name, domain);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getPermissionsForUserInDomain gets permissions for a user or role inside a domain.
     *
     * @param user   the user.
     * @param domain the domain.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    @Override
    public List<List<String>> getPermissionsForUserInDomain(String user, String domain) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getPermissionsForUserInDomain(user, domain);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * addRoleForUserInDomain adds a role for a user inside a domain.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user   the user.
     * @param role   the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    @Override
    public boolean addRoleForUserInDomain(String user, String role, String domain) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.addRoleForUserInDomain(user, role, domain);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * deleteRoleForUserInDomain deletes a role for a user inside a domain.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user   the user.
     * @param role   the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    @Override
    public boolean deleteRoleForUserInDomain(String user, String role, String domain) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            return super.deleteRoleForUserInDomain(user, role, domain);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * getImplicitRolesForUser gets implicit roles that a user has.
     * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
     * For example:
     * g, alice, role:admin
     * g, role:admin, role:user
     * <p>
     * getRolesForUser("alice") can only get: ["role:admin"].
     * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
     *
     * @param name   the user
     * @param domain the domain
     * @return implicit roles that a user has.
     */
    @Override
    public List<String> getImplicitRolesForUser(String name, String... domain) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getImplicitRolesForUser(name, domain);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * getImplicitPermissionsForUser gets implicit permissions for a user or role.
     * Compared to getPermissionsForUser(), this function retrieves permissions for inherited roles.
     * For example:
     * p, admin, data1, read
     * p, alice, data2, read
     * g, alice, admin
     * <p>
     * getPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
     * But getImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
     *
     * @param user the user.
     * @return implicit permissions for a user or role.
     */
    @Override
    public List<List<String>> getImplicitPermissionsForUser(String user) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return super.getImplicitPermissionsForUser(user);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }
}
