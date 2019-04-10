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
import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Helper;
import org.casbin.jcasbin.util.Util;

import java.io.*;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

/**
 * FileAdapter is the file adapter for Casbin.
 * It can load policy from file or save policy to file.
 */
public class FileAdapter implements Adapter {
    private String filePath = null;

    private boolean readOnly = false;
    private ByteArrayOutputStream byteArrayOutputStream = null;

    /**
     * FileAdapter is the constructor for FileAdapter.
     *
     * @param filePath the path of the policy file.
     */
    public FileAdapter(String filePath) throws FileNotFoundException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("Policy file can not be found. Path: " + filePath);
        }
        this.filePath = filePath;
    }

    /**
     * FileAdapter is the constructor for FileAdapter.
     *
     * @param inputStream
     */
    public FileAdapter(InputStream inputStream) throws IOException {
        readOnly = true;
        byteArrayOutputStream = new ByteArrayOutputStream();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
        IOUtils.copy(bufferedInputStream, byteArrayOutputStream);
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
                e.printStackTrace();
                throw new Error("file operator error");
            }
        }
        if (byteArrayOutputStream != null) {
            byteArrayOutputStream.reset();
            try (ByteArrayInputStream bis = new ByteArrayInputStream(byteArrayOutputStream.toByteArray())) {
                loadPolicyData(model, Helper::loadPolicyLine, bis);
            } catch (IOException e) {
                e.printStackTrace();
                throw new Error("file operator error");
            }
        }
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    @Override
    public void savePolicy(Model model) {
        if (readOnly) {
            throw new Error("Policy file can not writer, because use inputStream is readOnly");
        }
        if (filePath != null && !"".equals(filePath)) {
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


    private void loadPolicyData(Model model, Helper.loadPolicyLineHandler<String, Model> handler, InputStream inputStream) {
        try {
            List<String> lines = IOUtils.readLines(inputStream, Charset.forName("UTF-8"));
            lines.forEach(x -> handler.accept(x, model));
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("Policy load error");
        }
    }

    private void savePolicyFile(String text) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            IOUtils.write(text, fos, Charset.forName("UTF-8"));
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("Policy save error");
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
