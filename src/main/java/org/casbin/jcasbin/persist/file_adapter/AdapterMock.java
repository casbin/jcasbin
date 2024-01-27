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

package org.casbin.jcasbin.persist.file_adapter;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Helper;

public class AdapterMock implements Adapter {
    private String filePath;
    private String errorValue;

    public AdapterMock(String filePath) {
        this.filePath = filePath;
    }

    public void setMockErr(String errorToSet) {
        this.errorValue = errorToSet;
    }

    public Exception getMockErr() {
        if (errorValue != null && !errorValue.isEmpty()) {
            return new Exception(errorValue);
        }
        return null;
    }

    @Override
    public void loadPolicy(Model model) {
        try {
            loadPolicyFile(model, Helper::loadPolicyLine);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void savePolicy(Model model) {
    }

    @Override
    public void addPolicy(String sec, String ptype, List<String> rule) {

    }

    @Override
    public void removePolicy(String sec, String ptype, List<String> rule) {
    }

    @Override
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
    }

    private void loadPolicyFile(Model model, Helper.loadPolicyLineHandler<String, Model> handler) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                handler.accept(line, model);
            }
        }
    }
}
