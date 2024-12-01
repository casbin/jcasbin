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

public class CachedEnforcer extends Enforcer{

    private Duration expireTime;
    private Cache cache;
    private final AtomicBoolean enableCache = new AtomicBoolean(true);
    private final static ReadWriteLock READ_WRITE_LOCK = new ReentrantReadWriteLock();

    /**
     * Default constructor for CachedEnforcer.
     * Initializes a new CachedEnforcer with a default cache.
     */
    public CachedEnforcer(){
        super();
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath  The path of the model file.
     * @param policyFile The path of the policy file.
     */
    public CachedEnforcer(String modelPath, String policyFile){
        super(modelPath, policyFile);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file and a database adapter.
     *
     * @param modelPath The path of the model file.
     * @param adapter   The adapter for the database.
     */
    public CachedEnforcer(String modelPath, Adapter adapter) {
        super(modelPath, adapter);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model and a database adapter.
     *
     * @param m       The model.
     * @param adapter The adapter for the database.
     */
    public CachedEnforcer(Model m, Adapter adapter) {
        super(m, adapter);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model.
     *
     * @param m The model.
     */
    public CachedEnforcer(Model m) {
        super(m);
        this.cache = new DefaultCache();
    }

    /**
     * Initializes an enforcer with a model file.
     *
     * @param modelPath The path of the model file.
     */
    public CachedEnforcer(String modelPath) {
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
    public CachedEnforcer(String modelPath, String policyFile, boolean enableLog) {
        super(modelPath, policyFile, enableLog);
        this.cache = new DefaultCache();
    }

    /**
     * Retrieves the current cache used by this CachedEnforcer.
     *
     * @return The cache instance.
     */
    public Cache getCache() {
        return this.cache;
    }

    /**
     * Enforces a policy based on the given request values.
     *
     * @param rvals The request values, usually in the format of (sub, obj, act).
     * @return The result of the enforcement (true or false).
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

        boolean cachedResult = getCachedResult(key);
        if (cachedResult) {
            return cachedResult;
        }

        boolean result = super.enforce(rvals);
        setCachedResult(key, result, expireTime);
        return result;
    }


    /**
     * Loads policies into the enforcer.
     * If caching is enabled, clears the cache before loading policies.
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
     * Removes a policy from the enforcer.
     *
     * @param params The parameters of the policy to be removed.
     * @return True if the policy was removed, false otherwise.
     */
    @Override
    public boolean removePolicy(String... params){
        if (enableCache.get()) {
            String key = getKey((Object[]) params);
            if (key != null) {
                cache.delete(key);
            }
        }
        return super.removePolicy(params);
    }

    /**
     * Removes multiple policies from the enforcer.
     *
     * @param rules The list of policies to be removed.
     * @return True if the policies were removed, false otherwise.
     */
    @Override
    public boolean removePolicies(List<List<String>> rules) {
        if (!rules.isEmpty() && enableCache.get()) {
            for (List<String> rule : rules) {
                String key = getKey(rule.toArray());
                cache.delete(key);
            }
        }
        return super.removePolicies(rules);
    }

    /**
     * Removes multiple policies from the enforcer.
     *
     * @param rules The list of policies to be removed.
     * @return True if the policies were removed, false otherwise.
     */
    @Override
    public boolean removePolicies(String[][] rules) {
        if (rules != null && enableCache.get()) {
            for (String[] rule : rules) {
                String key = getKey((Object[]) rule);
                cache.delete(key);
            }
        }
        return super.removePolicies(rules);
    }

    /**
     * Retrieves a cached result based on the key.
     *
     * @param key The cache key.
     * @return The cached result, or null if not found.
     */
    private boolean getCachedResult(String key) {
        READ_WRITE_LOCK.readLock().lock();
        try {
            return cache.get(key);
        }finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    /**
     * Sets the expiration time for cached items.
     *
     * @param expireTime The duration after which cached items will expire.
     */
    public void setExpireTime(Duration expireTime) {
        this.expireTime = expireTime;
    }

    /**
     * Sets a custom cache implementation.
     *
     * @param cache The cache instance to use.
     */
    public void setCache(Cache cache) {
        this.cache = cache;
    }

    /**
     * Stores a result in the cache with an expiration time.
     *
     * @param key        The cache key.
     * @param result     The result to cache.
     * @param expireTime The duration for which the result should be cached.
     */
    private void setCachedResult(String key, boolean result, Duration expireTime) {
        READ_WRITE_LOCK.writeLock().lock();
        try {
            cache.set(key, result, expireTime);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * Generates a cache key from the given parameters.
     *
     * @param params The parameters for generating the key.
     * @return The generated cache key, or null if invalid parameters are provided.
     */
    private String getKey(Object... params) {
        StringBuilder keyBuilder = new StringBuilder();
        for (Object param : params) {
            if (param instanceof String) {
                keyBuilder.append(param);
            } else if (param instanceof CacheableParam) {
                keyBuilder.append(((CacheableParam) param).getCacheKey());
            } else {
                return null;
            }
            keyBuilder.append("$$");
        }
        return keyBuilder.toString();
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
                // Return an error identifier
                return "";
            }
            key.append("$$");
        }
        // Return the constructed key
        return key.toString();
    }

    /**
     * Invalidates all cached decisions.
     */
    public void invalidateCache() {
        READ_WRITE_LOCK.writeLock().lock();
        try {
            cache.clear();
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    /**
     * Clears all policies from the enforcer.
     * If caching is enabled, clears the cache before clearing policies.
     */
    @Override
    public void clearPolicy() {
        if (enableCache.get()) {
            try {
                cache.clear();
            } catch (Exception e) {
                // Handle the error
            }
        }
        super.clearPolicy();
    }
}
