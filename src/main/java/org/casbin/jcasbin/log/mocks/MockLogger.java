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

package org.casbin.jcasbin.log.mocks;

import org.casbin.jcasbin.log.Logger;

import java.util.Map;

public class MockLogger implements Logger {
    private boolean enabled;

    public MockLogger() {
        this.enabled = true;
    }

    @Override
    public void enableLog(boolean enable) {
        this.enabled = enable;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void logModel(String[][] model) {
        System.out.println("MockLogger - logModel");
    }

    @Override
    public void logEnforce(String matcher, Object[] request, boolean result, String[][] explains) {
        System.out.println("MockLogger - logEnforce");
    }

    @Override
    public void logRole(String[] roles) {
        System.out.println("MockLogger - logRole");
    }

    @Override
    public void logPolicy(Map<String, String[][]> policy) {
        System.out.println("MockLogger - logPolicy");
    }

    @Override
    public void logError(Throwable err, String... msg) {
        System.out.println("MockLogger - logError");
    }
}
