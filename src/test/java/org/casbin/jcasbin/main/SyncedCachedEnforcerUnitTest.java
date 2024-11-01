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

import org.junit.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

public class SyncedCachedEnforcerUnitTest {

    private void testSyncEnforceCache(SyncedCachedEnforcer e, String sub, Object obj, String act, boolean res) {
        boolean myRes = e.enforce(sub, obj, act);
        assertEquals(String.format("%s, %s, %s: %b, supposed to be %b", sub, obj, act, myRes, res), res, myRes);
    }

    @Test
    public void testSyncCache() throws Exception {
        final SyncedCachedEnforcer enforcer = new SyncedCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv");
        enforcer.setExpireTime(Duration.ofMillis(1));

        int goThread = 1000;
        CountDownLatch latch = new CountDownLatch(goThread);

        for (int i = 0; i < goThread; i++) {
            new Thread(() -> {
                enforcer.addPolicy("alice", "data2", "read");
                testSyncEnforceCache(enforcer, "alice", "data2", "read", true);
                enforcer.invalidateCache();
                latch.countDown();
            }).start();
        }
        latch.await();

        enforcer.removePolicy("alice", "data2", "read");

        testSyncEnforceCache(enforcer, "alice", "data1", "read", true);
        TimeUnit.MILLISECONDS.sleep(2);
        testSyncEnforceCache(enforcer, "alice", "data1", "read", true);

        testSyncEnforceCache(enforcer, "alice", "data1", "write", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "read", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "write", false);

        enforcer.removePolicy("alice", "data1", "read");

        testSyncEnforceCache(enforcer, "alice", "data1", "read", false);
        testSyncEnforceCache(enforcer, "alice", "data1", "write", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "read", false);
        testSyncEnforceCache(enforcer, "alice", "data2", "write", false);


        SyncedCachedEnforcer syncedCachedEnforcer = new SyncedCachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");

        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data1", "read", true);
        testSyncEnforceCache(syncedCachedEnforcer, "bob", "data2", "write", true);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "read", true);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "write", true);

        syncedCachedEnforcer.removePolicies(new String[][]{
            {"alice", "data1", "read"},
            {"bob", "data2", "write"},
        });

        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data1", "read", false);
        testSyncEnforceCache(syncedCachedEnforcer, "bob", "data2", "write", false);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "read", true);
        testSyncEnforceCache(syncedCachedEnforcer, "alice", "data2", "write", true);
    }
}
