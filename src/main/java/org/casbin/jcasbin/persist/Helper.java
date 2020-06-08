// Copyright 2018 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.persist;

import static org.casbin.jcasbin.util.Util.splitCommaDelimited;

import org.casbin.jcasbin.model.Model;

import java.util.Arrays;

public class Helper {
    public interface loadPolicyLineHandler<T, U> {
        void accept(T t, U u);
    }

    public static void loadPolicyLine(String line, Model model) {
        if (line.equals("")) {
            return;
        }

        if (line.charAt(0) == '#') {
            return;
        }

        String[] tokens = splitCommaDelimited(line);

        String key = tokens[0];
        String sec = key.substring(0, 1);
        model.model.get(sec).get(key).policy.add(Arrays.asList(Arrays.copyOfRange(tokens, 1, tokens.length)));
    }
}
