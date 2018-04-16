// Copyright 2017 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.persist.file_adapter;

import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Helper;
import org.casbin.jcasbin.util.Util;

import java.io.*;
import java.util.List;
import java.util.Map;

/**
 * FileAdapter is the file adapter for Casbin.
 * It can load policy from file or save policy to file.
 */
public class FileAdapter implements Adapter {
    private String filePath;

    /**
     * FileAdapter is the constructor for FileAdapter.
     *
     * @param filePath the path of the policy file.
     */
    public FileAdapter(String filePath) {
        this.filePath = filePath;
    }

    /**
     * loadPolicy loads all policy rules from the storage.
     */
    @Override
    public void loadPolicy(Model model) {
        if (filePath.equals("")) {
            // throw new Error("invalid file path, file path cannot be empty");
            return;
        }

        loadPolicyFile(model, Helper::loadPolicyLine);
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    @Override
    public void savePolicy(Model model) {
        if (filePath.equals("")) {
            throw new Error("invalid file path, file path cannot be empty");
        }

        StringBuilder tmp = new StringBuilder();

        for (Map.Entry<String, Assertion> entry : model.model.get("p").entrySet()) {
            String ptype = entry.getKey();
            Assertion ast = entry.getValue();

            for (List<String> rule : ast.policy) {
                tmp.append(ptype + ", ");
                tmp.append(Util.arrayToString(rule));
                tmp.append("\n");
            }
        }

        for (Map.Entry<String, Assertion> entry : model.model.get("g").entrySet()) {
            String ptype = entry.getKey();
            Assertion ast = entry.getValue();

            for (List<String> rule : ast.policy) {
                tmp.append(ptype + ", ");
                tmp.append(Util.arrayToString(rule));
                tmp.append("\n");
            }
        }

        savePolicyFile(tmp.toString().trim());
    }


    private void loadPolicyFile(Model model, Helper.loadPolicyLineHandler<String, Model> handler) {
        FileInputStream fis;
        try {
            fis = new FileInputStream(filePath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new Error("policy file not found");
        }
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));

        String line;
        try {
            while((line = br.readLine()) != null)
            {
                handler.accept(line, model);
            }

            fis.close();
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("IO error occurred");
        }
    }

    private void savePolicyFile(String text) {
        try {
            FileOutputStream fos = new FileOutputStream(filePath);
            fos.write(text.getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("IO error occurred");
        }
    }

    /**
     * addPolicy adds a policy rule to the storage.
     */
    @Override
    public void addPolicy(String sec, String ptype, List<String> rule) {
        throw new Error("not implemented");
    }

    /**
     * removePolicy removes a policy rule from the storage.
     */
    @Override
    public void removePolicy(String sec, String ptype, List<String> rule) {
        throw new Error("not implemented");
    }

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     */
    @Override
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        throw new Error("not implemented");
    }
}
