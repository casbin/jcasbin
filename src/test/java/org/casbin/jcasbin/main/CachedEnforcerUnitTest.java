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

import org.casbin.jcasbin.persist.cache.Cache;
import org.casbin.jcasbin.persist.cache.CacheableParam;
import org.casbin.jcasbin.persist.cache.DefaultCache;
import org.testng.annotations.Test;

import java.time.Duration;

import static org.testng.Assert.*;

public class CachedEnforcerUnitTest {
    private CachedEnforcer cachedEnforcer;

    private Cache cache;

    private void testEnforceCache(String sub, String obj, String act, boolean expectedRes) throws Exception {
        Boolean actualRes = cachedEnforcer.enforce(sub, obj, act);
        assertEquals(actualRes, expectedRes, String.format("%s, %s, %s: %s, supposed to be %s", sub, obj, act, actualRes, expectedRes));
    }

    @Test
    public void testCache() throws Exception {
        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        // Test initial policy enforcement
        testEnforceCache("alice", "data1", "read", true);
        testEnforceCache("alice", "data1", "write", false);
        testEnforceCache("alice", "data2", "read", false);
        testEnforceCache("alice", "data2", "write", false);

        // Remove policy and check enforcement results
        cachedEnforcer.removePolicy("alice", "data1", "read");
        testEnforceCache("alice", "data1", "read", false);
        testEnforceCache("alice", "data1", "write", false);
        testEnforceCache("alice", "data2", "read", false);
        testEnforceCache("alice", "data2", "write", false);

        // Initialize another CachedEnforcer with a different model and policy
        cachedEnforcer = new CachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testEnforceCache("alice", "data1", "read", true);
        testEnforceCache("bob", "data2", "write", true);
        testEnforceCache("alice", "data2", "read", true);
        testEnforceCache("alice", "data2", "write", true);

        cachedEnforcer.removePolicies(new String[][]{
            {"alice", "data1", "read"},
            {"bob", "data2", "write"},
        });

        testEnforceCache("alice", "data1", "read", false);
        testEnforceCache("bob", "data2", "write", false);
        testEnforceCache("alice", "data2", "read", true);
        testEnforceCache("alice", "data2", "write", true);

        // Re-initialize to ensure policies are loaded correctly
        cachedEnforcer = new CachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        testEnforceCache("alice", "data1", "read", true);
        testEnforceCache("bob", "data2", "write", true);
        testEnforceCache("alice", "data2", "read", true);
        testEnforceCache("alice", "data2", "write", true);

        // Clear all policies and check results
        cachedEnforcer.clearPolicy();

        testEnforceCache("alice", "data1", "read", false);
        testEnforceCache("bob", "data2", "write", false);
        testEnforceCache("alice", "data2", "read", false);
        testEnforceCache("alice", "data2", "write", false);
    }

    @Test
    public void testInvalidateCache() throws Exception {
        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv", false);

        Boolean cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertNull(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, null));

        Boolean actualRes = cachedEnforcer.enforce("alice", "data1", "read");
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertTrue(actualRes, String.format("alice, data1, read: %s, supposed to be %s", actualRes, true));
        assertTrue(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, true));

        cachedEnforcer.invalidateCache();
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertNull(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, null));

    }

    /**
     * Generates a cache key based on the provided parameters.
     *
     * @param params Variable arguments of type Object that will be used to construct the cache key.
     *               The method expects parameters to be either Strings or instances of CacheableParam.
     * @return A String representing the constructed cache key, or null if an unsupported type is encountered.
     */
    String getKey(Object... params) {
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

    @Test
    public void testCacheExpiration() throws Exception {
        cachedEnforcer = new CachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        cache = new DefaultCache();
        cachedEnforcer.setExpireTime(Duration.ofMillis(10));

        // Test cache expiration
        cache.set(getKey("alice", "data1", "read"),true,Duration.ofMillis(10));
        cachedEnforcer.setCache(cache);
        Boolean cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertTrue(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, true));

        // Wait for the cache to expire
        Thread.sleep(15);

        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("alice", "data1", "read"));
        assertNull(cacheKey, String.format("alice, data1, read: %s, supposed to be %s", cacheKey, null));

        // Replace cache during test run
        cache.clear();
        cache.set(getKey("bob", "data1", "read"),true,Duration.ofMillis(1000));
        cachedEnforcer.setCache(cache);
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("bob", "data1", "read"));
        assertTrue(cacheKey, String.format("bob, data1, read: %s, supposed to be %s", cacheKey, true));

        cache.clear();
        cache.set(getKey("jack", "data1", "write"),true,Duration.ofMillis(1000));
        cachedEnforcer.setCache(cache);
        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("bob", "data1", "read"));
        assertNull(cacheKey, String.format("bob, data1, read: %s, supposed to be %s", cacheKey, null));

        cacheKey = cachedEnforcer.getCache().get(cachedEnforcer.getCacheKey("jack", "data1", "write"));
        assertTrue(cacheKey, String.format("jack, data1, write: %s, supposed to be %s", cacheKey, true));
    }
}
