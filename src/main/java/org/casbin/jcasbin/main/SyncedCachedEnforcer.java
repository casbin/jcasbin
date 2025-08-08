// Copyright 2024 The casbin Authors. All Rights Reserved.
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
import org.casbin.jcasbin.persist.cache.Cache;
import org.casbin.jcasbin.persist.cache.CacheableParam;
import org.casbin.jcasbin.persist.cache.DefaultCache;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class SyncedCachedEnforcer extends SyncedEnforcer{
    private Duration expireTime;
    private Cache cache;
    private final AtomicBoolean enableCache = new AtomicBoolean(true);
    private final static ReadWriteLock READ_WRITE_LOCK = new ReentrantReadWriteLock();

    /**
     * Default constructor. Initializes a new SyncedCachedEnforcer with a default cache.
     */
    public SyncedCachedEnforcer(){
        super();
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath  The path of the model file.
     * @param policyFile The path of the policy file.
     */
    public SyncedCachedEnforcer(String modelPath, String policyFile){
        super(modelPath, policyFile);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file and a database adapter.
     *
     * @param modelPath The path of the model file.
     * @param adapter   The adapter for the database.
     */
    public SyncedCachedEnforcer(String modelPath, Adapter adapter) {
        super(modelPath, adapter);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model and a database adapter.
     *
     * @param m       The model.
     * @param adapter The adapter for the database.
     */
    public SyncedCachedEnforcer(Model m, Adapter adapter) {
        super(m, adapter);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model.
     *
     * @param m The model.
     */
    public SyncedCachedEnforcer(Model m) {
        super(m);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file.
     *
     * @param modelPath The path of the model file.
     */
    public SyncedCachedEnforcer(String modelPath) {
        super(modelPath);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file, a policy file, and a logging flag.
     *
     * @param modelPath  The path of the model file.
     * @param policyFile The path of the policy file.
     * @param enableLog  Whether to enable logging for Casbin.
     */
    public SyncedCachedEnforcer(String modelPath, String policyFile, boolean enableLog) {
        super(modelPath, policyFile, enableLog);
        this.cache = new DefaultCache();
    }

    /**
     * Enables or disables caching.
     *
     * @param enable Whether to enable caching.
     */
    public void enableCache(boolean enable) {
        enableCache.set(enable);
    }

    /**
     * Performs an enforcement check based on given parameters, using the cache.
     *
     * @param rvals Parameters for the enforcement check.
     * @return The result of the enforcement check.
     */
    @Override
    public boolean enforce(Object... rvals) {
        if (!enableCache.get()) {
            return super.enforce(rvals);
        }

        String key = getKey(rvals);
        if (key == null) {
            return super.enforce(rvals);
        }

        Boolean cachedResult = getCachedResult(key);
        if (cachedResult != null) {
            return cachedResult;
        }

        boolean result = super.enforce(rvals);
        setCachedResult(key, result, expireTime);
        return result;
    }

    /**
     * Loads the policy, clearing the cache if enabled.
     */
    @Override
    public void loadPolicy() {
        if(enableCache == null || !enableCache.get()){
            super.loadPolicy();
        } else {
            if (enableCache.get()) {
                cache.clear();
            }
            super.loadPolicy();
        }
    }

    /**
     * Adds a single policy while checking and removing the cache.
     *
     * @param params Policy parameters.
     * @return Whether the addition was successful.
     */
    @Override
    public boolean addPolicy(String... params) {
        if (!checkOneAndRemoveCache(params)) {
            return false;
        }
        return super.addPolicy(params);
    }

    /**
     * Adds multiple policies while checking and removing the cache.
     *
     * @param rules Policy rules.
     * @return Whether the addition was successful.
     */
    @Override
    public boolean addPolicies(List<List<String>> rules) {
        if (!checkManyAndRemoveCache(rules)) {
            return false;
        }
        return super.addPolicies(rules);
    }

    /**
     * Adds multiple policies while checking and removing the cache.
     *
     * @param rules Policy rules.
     * @return Whether the addition was successful.
     */
    @Override
    public boolean addPolicies(String[][] rules) {
        if (!checkManyAndRemoveCache(rules)) {
            return false;
        }
        return super.addPolicies(rules);
    }

    /**
     * Removes a single policy while checking and removing the cache.
     *
     * @param params Policy parameters.
     * @return Whether the removal was successful.
     */
    @Override
    public boolean removePolicy(String... params) {
        if (!checkOneAndRemoveCache(params)) {
            return false;
        }
        return super.removePolicy(params);
    }

    /**
     * Removes multiple policies while checking and removing the cache.
     *
     * @param rules Policy rules.
     * @return Whether the removal was successful.
     */
    @Override
    public boolean removePolicies(List<List<String>>rules) {
        if (!checkManyAndRemoveCache(rules)) {
            return false;
        }
        return super.removePolicies(rules);
    }

    /**
     * Removes multiple policies while checking and removing the cache.
     *
     * @param rules Policy rules.
     * @return Whether the removal was successful.
     */
    @Override
    public boolean removePolicies(String[][] rules) {
        if (!checkManyAndRemoveCache(rules)) {
            return false;
        }
        return super.removePolicies(rules);
    }

    /**
     * Retrieves a cached result based on the given key.
     *
     * @param key The cache key.
     * @return The cached result.
     */
    private Boolean getCachedResult(String key) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return cache.get(key);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * Sets the cache expiration time.
     *
     * @param expireTime The expiration time.
     */
    public void setExpireTime(Duration expireTime) {
        READ_WRITE_LOCK.writeLock().lock();
        try {
            this.expireTime = expireTime;
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * Sets a custom cache.
     *
     * @param cache The custom cache.
     */
    public void setCache(Cache cache) {
        READ_WRITE_LOCK.writeLock().lock();
        try {
            this.cache = cache;
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * Sets the cached result.
     *
     * @param key    The cache key.
     * @param result The enforcement check result.
     * @param extra  Additional parameters.
     */
    private void setCachedResult(String key, boolean result, Object... extra) {
        cache.set(key, result, extra);
    }

    /**
     * Retrieves a cache key from the given parameters.
     *
     * @param params The parameters for generating the key.
     * @return The generated cache key as a string.
     */
    public String getCacheKey(Object... params) {
        StringBuilder key = new StringBuilder();
        for (Object param : params) {
            if (param instanceof String) {
                key.append((String) param);
            } else if (param instanceof CacheableParam) {
                key.append(((CacheableParam) param).getCacheKey());
            } else {
                return "";
            }
            key.append("$$");
        }
        return key.toString();
    }

    /**
     * Generates a key based on the given parameters.
     *
     * @param params Parameters.
     * @return The generated key.
     */
    private String getKey(Object... params) {
        return getCacheKey(params);
    }

    /**
     * Invalidates the cache by clearing it.
     */
    public void invalidateCache() {
        cache.clear();
    }

    /**
     * Checks and removes cache for a single policy.
     *
     * @param params Policy parameters.
     * @return Whether the check was successful.
     */
    private boolean checkOneAndRemoveCache(String... params) {
        if (enableCache.get()) {
            String key = getKey((Object []) params);
            if (key != null) {
                cache.delete(key);
            }
        }
        return true;
    }

    /**
     * Checks and removes cache for multiple policies.
     *
     * @param rules Policy rules.
     * @return Whether the check was successful.
     */
    private boolean checkManyAndRemoveCache(List<List<String>> rules) {
        if (!rules.isEmpty() && enableCache.get()) {
            for (List<String> rule : rules) {
                String key = getKey(rule.toArray());
                if (key != null) {
                    cache.delete(key);
                }
            }
        }
        return true;
    }

    /**
     * Checks and removes cache for multiple policies.
     *
     * @param rules Policy rules.
     * @return Whether the check was successful.
     */
    private boolean checkManyAndRemoveCache(String[][] rules) {
        if (rules != null && enableCache.get()) {
            for (String[] rule : rules) {
                String key = getKey((Object[]) rule);
                if (key != null) {
                    cache.delete(key);
                }
            }
        }
        return true;
    }
}
