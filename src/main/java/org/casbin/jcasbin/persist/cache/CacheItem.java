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

import java.time.Duration;
import java.time.LocalDateTime;

public class CacheItem {
    private boolean value;
    private LocalDateTime expiresAt;
    private Duration ttl;

    CacheItem(){}

    /**
     * Constructs a CacheItem with a specified value and time-to-live (ttl).
     *
     * @param value The boolean value to be cached.
     * @param ttl   The duration for which this item should remain in the cache.
     */
    public CacheItem(boolean value, Duration ttl) {
        this.value = value;
        this.ttl = ttl;
        if (!ttl.isNegative()) {
            this.expiresAt = LocalDateTime.now().plus(ttl);
        }
    }

    /**
     * Checks whether the cache item has expired based on the current time and its ttl.
     *
     * @return True if the cache item is expired, false otherwise.
     */
    public boolean isExpired() {
        return !ttl.isNegative() && LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Retrieves the cached value.
     *
     * @return The boolean value stored in this cache item.
     */
    public boolean getValue() {
        return value;
    }
}
