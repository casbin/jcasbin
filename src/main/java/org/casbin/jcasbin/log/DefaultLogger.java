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

public class DefaultLogger implements Logger {
    private boolean enabled;

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
        if (!enabled) {
            return;
        }

        StringBuilder str = new StringBuilder("Model: ");
        for (String[] v : model) {
            str.append(String.format("%s\n", String.join(", ", v)));
        }

        System.out.println(str.toString());
    }

    @Override
    public void logEnforce(String matcher, Object[] request, boolean result, String[][] explains) {
        if (!enabled) {
            return;
        }

        StringBuilder reqStr = new StringBuilder("Request: ");
        for (int i = 0; i < request.length; i++) {
            reqStr.append(i != request.length - 1 ? String.format("%s, ", request[i]) : request[i]);
        }
        reqStr.append(String.format(" ---> %b\n", result));

        reqStr.append("Hit Policy: ");
        for (int i = 0; i < explains.length; i++) {
            reqStr.append(i != explains.length - 1 ? String.format("%s, ", String.join(", ", explains[i])) : String.join(", ", explains[i]));
        }

        System.out.println(reqStr.toString());
    }

    @Override
    public void logPolicy(Map<String, String[][]> policy) {
        if (!enabled) {
            return;
        }

        StringBuilder str = new StringBuilder("Policy: ");
        for (Map.Entry<String, String[][]> entry : policy.entrySet()) {
            str.append(String.format("%s : %s\n", entry.getKey(), arrayToString(entry.getValue())));
        }

        System.out.println(str.toString());
    }

    /**
     * tool for logPolicy
     * [][] -> String
     */
    private String arrayToString(String[][] array) {
        StringBuilder result = new StringBuilder("[");
        for (int i = 0; i < array.length; i++) {
            result.append("[")
                .append(String.join(", ", array[i]))
                .append("]");
            if (i < array.length - 1) {
                result.append(", ");
            }
        }
        result.append("]");
        return result.toString();
    }


    @Override
    public void logRole(String[] roles) {
        if (!enabled) {
            return;
        }

        System.out.println("Roles: " + String.join("\n", roles));
    }

    @Override
    public void logError(Throwable err, String... msg) {
        if (!enabled) {
            return;
        }

        System.out.println(String.join(" ", msg) + " " + err.getMessage());
    }
}
