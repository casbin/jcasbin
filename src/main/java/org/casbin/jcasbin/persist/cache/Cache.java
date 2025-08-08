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

public interface Cache {
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
    boolean set(String key, boolean value, Object... extra);



    /**
     * Get returns the result for the given key.
     * If there's no such key in the cache, Optional.empty() will be returned.
     *
     * @param key the key to retrieve
     * @return an Optional containing the boolean value if present, otherwise Optional.empty()
     */
    Boolean get(String key);

    /**
     * Delete removes the specific key from the cache.
     * If the key doesn't exist, it returns false.
     *
     * @param key the key to delete
     */
    void delete(String key);

    /**
     * Clear deletes all items stored in the cache.
     *
     */
    void clear();
}
