// Copyright 2021 The casbin Authors. All Rights Reserved.
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

import com.google.gson.Gson;
import org.casbin.jcasbin.model.Model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Frontend {

    /**
     * casbinJsGetPermissionForUser gets permissions for a user or role in json format.
     * @param e the enforcer.
     * @param user the user.
     * @return model, pRules, gRules in json format.
     */
    public static String casbinJsGetPermissionForUser(Enforcer e, String user) {
        Model model = e.getModel();
        Map<String, Object> m = new HashMap<>();
        m.put("m", model.saveModelToText().trim());

        m.put("p", getRulesBySection(model, "p"));
        m.put("g", getRulesBySection(model, "g"));
        return new Gson().toJson(m);
    }

    private static List<List<String>> getRulesBySection(Model model, String sec) {
        List<List<String>> rules = new ArrayList<>();
        for (String ptype : model.model.get(sec).keySet()) {
            List<List<String>> policy = model.getPolicy(sec, ptype);
            for (List<String> p : policy) {
                List<String> tmp = new ArrayList<>(p);
                tmp.add(0, ptype);
                rules.add(tmp);
            }
        }
        return rules;
    }
}
