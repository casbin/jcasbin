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

package org.casbin.jcasbin.log;

import java.util.Map;

public interface Logger {
    void enableLog(boolean enable);

    boolean isEnabled();

    void logModel(String[][] model);

    void logEnforce(String matcher, Object[] request, boolean result, String[][] explains);

    void logRole(String[] roles);

    void logPolicy(Map<String, String[][]> policy);

    void logError(Throwable err, String... msg);
}
