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

public class LogUtil {
    private static Logger logger = new DefaultLogger();

    public static void setLogger(Logger l) {
        logger = l;
    }

    public static Logger getLogger() {
        return logger;
    }

    public static void logModel(String[][] model) {
        logger.logModel(model);
    }

    public static void logEnforce(String matcher, Object[] request, boolean result, String[][] explains) {
        logger.logEnforce(matcher, request, result, explains);
    }

    public static void logRole(String[] roles) {
        logger.logRole(roles);
    }

    public static void logPolicy(Map<String, String[][]> policy) {
        logger.logPolicy(policy);
    }

    public static void logError(Throwable err, String... msg) {
        logger.logError(err, msg);
    }
}
