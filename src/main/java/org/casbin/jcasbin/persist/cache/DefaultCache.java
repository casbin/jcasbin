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

package org.casbin.jcasbin.persist.cache;

import org.casbin.jcasbin.exception.CasbinCacheException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class DefaultCache implements Cache {
    private final Map<String, CacheItem> cache;

    public DefaultCache() {
        this.cache = new HashMap<>();
    }

    /**
     * Set the cache value with an optional time-to-live (TTL).
     *
     * @param key   The cache key to store the value.
     * @param value The boolean value to be stored in the cache.
     * @param ttl   The time-to-live for the cache item; if null or negative, the item will not expire.
     */
    public void set(String key, boolean value, Duration ttl) {
        CacheItem item = new CacheItem(value, ttl);
        cache.put(key, item);
    }

    /**
     * Set the cache value without a TTL.
     *
     * @param key   The cache key to store the value.
     * @param value The boolean value to be stored in the cache.
     */
    public void set(String key, boolean value) {
        CacheItem item = new CacheItem(value, Duration.ofMillis(-1));
        cache.put(key, item);
    }


    /**
     * Set puts key and value into cache.
     * The first extra parameter should be a java.time.LocalDateTime object denoting the expected survival time.
     * If survival time equals 0 or less, the key will always be valid.
     *
     * @param key   the key to store
     * @param value the value to store
     * @param extra additional parameters (e.g., expiration time)
     * @return true if successful, false otherwise
     */
    @Override
    public boolean set(String key, boolean value, Object... extra) {
        if (extra.length > 0 && extra[0] instanceof Duration) {
            Duration ttl = (Duration) extra[0];
            set(key, value, ttl);
        } else {
            set(key, value);
        }
        return true; // assuming set always succeeds
    }

    /**
     * Get the value from the cache, handling expiration.
     *
     * @param key The cache key to retrieve the value.
     * @throws CasbinCacheException If the key does not exist in the cache.
     * @return The value corresponding to the key.
     */
    public boolean get(String key) {
        CacheItem item = cache.get(key);
        if (item == null) {
            return false;
        }
        if (item.isExpired()) {
            cache.remove(key);
            return false;
        }
        return item.getValue();
    }

    /**
     * Delete the value from the cache.
     *
     * @param key The cache key to delete the value.
     */
    public void delete(String key) throws CasbinCacheException {
        cache.remove(key);
    }

    /**
     * Clear the entire cache.
     */
    public void clear() {
        cache.clear();
    }
}
