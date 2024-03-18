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

import org.casbin.jcasbin.persist.Watcher;
import org.junit.Assert;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.junit.Assert.fail;

public class WatcherTest {
    public static class SampleWatcher implements Watcher {
        Consumer<String> callback;

        @Override
        public void setUpdateCallback(Runnable runnable) {
            callback = (s) -> {
                runnable.run();
            };
        }

        @Override
        public void setUpdateCallback(Consumer<String> func) {
            callback = func;
        }

        @Override
        public void update() {
            if (callback != null) {
                callback.accept("");
            }
        }
    }


    @Test
    public void testSetWatcher() {
        Enforcer enforcer = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        AtomicBoolean status = new AtomicBoolean(false);
        SampleWatcher thisIsTestWatcher = new SampleWatcher();
        enforcer.setWatcher(thisIsTestWatcher);
        enforcer.watcher.setUpdateCallback((s) -> {
            status.set(true);
        });
        enforcer.savePolicy();//calls watcher.Update()
        Assert.assertTrue(status.get());
    }

    @Test
    public void testSelfModify() {
        Enforcer enforcer = new Enforcer("examples/rbac_model.conf", "examples/rbac_policy.csv");
        SampleWatcher thisIsTestWatcher = new SampleWatcher();
        enforcer.setWatcher(thisIsTestWatcher);
        AtomicInteger called = new AtomicInteger(-1);
        enforcer.watcher.setUpdateCallback((s) -> {
            called.set(1);
        });
        boolean r = enforcer.addPolicy("eva", "data", "read");//calls watcher.Update()
        if (!r) {
            fail("addPolicy error");
        }
        if (called.get() != 1) {
            fail("callback should be called");
        }
        //todo SelfAddPolicy
    }
}
