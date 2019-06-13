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

import org.apache.commons.io.IOUtils;
import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.exception.CasbinPolicyFileNotFoundException;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Helper;
import org.casbin.jcasbin.util.Util;

import java.io.*;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * FileAdapter is the file adapter for Casbin.
 * It can load policy from file or save policy to file.
 */
public class FileAdapter implements Adapter {
    private String filePath;
    private boolean readOnly = false;
    private ByteArrayInputStream byteArrayInputStream;

    /**
     * FileAdapter is the constructor for FileAdapter.
     *
     * @param filePath the path of the policy file.
     */
    public FileAdapter(String filePath) {
        this.filePath = filePath;
    }

    /**
     * FileAdapter is the constructor for FileAdapter.
     *
     * @param inputStream the policy file.inputStream
     */
    public FileAdapter(InputStream inputStream) {
        readOnly = true;
        try {
            byteArrayInputStream = new ByteArrayInputStream(IOUtils.toByteArray(inputStream));
        } catch (IOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("File adapter init error");
        }
    }

    /**
     * loadPolicy loads all policy rules from the storage.
     */
    @Override
    public void loadPolicy(Model model) {
        if (filePath != null && !"".equals(filePath)) {
            try (FileInputStream fis = new FileInputStream(filePath)) {
                loadPolicyData(model, Helper::loadPolicyLine, fis);
            } catch (IOException e) {
                throw new CasbinAdapterException("Load policy file error", e.getCause());
            }
        }
        if (byteArrayInputStream != null) {
            loadPolicyData(model, Helper::loadPolicyLine, byteArrayInputStream);
        }
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    @Override
    public void savePolicy(Model model) {
        if (byteArrayInputStream != null && readOnly) {
            throw new CasbinAdapterException("Policy file can not write, because use inputStream is readOnly");
        }
        if (filePath == null || "".equals(filePath) || !new File(filePath).exists()) {
            throw new CasbinPolicyFileNotFoundException("invalid file path: " + filePath);
        }

        List<String> policy = new ArrayList<>();
        policy.addAll(getModelPolicy(model, "p"));
        policy.addAll(getModelPolicy(model, "g"));

        savePolicyFile(String.join("\n", policy));
    }

    private List<String> getModelPolicy(Model model, String ptype) {
        List<String> policy = new ArrayList<>();
        model.model.get(ptype).forEach((k, v) -> {
            List<String> p = v.policy.parallelStream().map(x -> k + ", " + Util.arrayToString(x)).collect(Collectors.toList());
            policy.addAll(p);
        });
        return policy;
    }

    private void loadPolicyData(Model model, Helper.loadPolicyLineHandler<String, Model> handler, InputStream inputStream) {
        try {
            List<String> lines = IOUtils.readLines(inputStream, Charset.forName("UTF-8"));
            lines.forEach(x -> handler.accept(x, model));
        } catch (IOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("Policy load error");
        }
    }

    private void savePolicyFile(String text) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            IOUtils.write(text, fos, Charset.forName("UTF-8"));
        } catch (IOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("Policy save error");
        }
    }

    /**
     * addPolicy adds a policy rule to the storage.
     */
    @Override
    public void addPolicy(String sec, String ptype, List<String> rule) {
        throw new UnsupportedOperationException("not implemented");
    }

    /**
     * removePolicy removes a policy rule from the storage.
     */
    @Override
    public void removePolicy(String sec, String ptype, List<String> rule) {
        throw new UnsupportedOperationException("not implemented");
    }

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     */
    @Override
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        throw new UnsupportedOperationException("not implemented");
    }
}
