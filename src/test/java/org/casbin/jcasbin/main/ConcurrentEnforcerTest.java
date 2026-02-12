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

import org.testng.annotations.Test;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Test for concurrent access to enforcer to verify race condition fixes.
 */
public class ConcurrentEnforcerTest {

    @Test
    public void testConcurrentEnforceAndAddPolicy() throws InterruptedException {
        // This test reproduces the race condition where policy.size() is read
        // multiple times during enforcement, potentially causing ArrayIndexOutOfBoundsException
        
        DistributedEnforcer enforcer = new DistributedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        
        int numThreads = 10;
        int iterations = 100;
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numThreads);
        AtomicBoolean errorOccurred = new AtomicBoolean(false);
        
        // Half threads add policies, half enforce
        for (int t = 0; t < numThreads; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    for (int i = 0; i < iterations; i++) {
                        if (threadId % 2 == 0) {
                            // Add and remove policies to change policy list size
                            String user = "user" + threadId + "_" + i;
                            String resource = "data" + (i % 3);
                            enforcer.addPolicy(user, resource, "read");
                            enforcer.removePolicy(user, resource, "read");
                        } else {
                            // Continuously enforce to trigger the race condition
                            try {
                                enforcer.enforce("alice", "data1", "read");
                            } catch (ArrayIndexOutOfBoundsException e) {
                                errorOccurred.set(true);
                                System.err.println("ArrayIndexOutOfBoundsException caught: " + e.getMessage());
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    latch.countDown();
                }
            });
        }
        
        assertTrue(latch.await(30, TimeUnit.SECONDS), "Test timeout");
        executor.shutdown();
        
        // With the fix, no ArrayIndexOutOfBoundsException should occur
        assertFalse(errorOccurred.get(), "ArrayIndexOutOfBoundsException occurred during concurrent access");
    }
}
