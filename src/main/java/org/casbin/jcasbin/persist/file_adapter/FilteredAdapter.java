// Copyright 2020 The casbin Authors. All Rights Reserved.
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
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Helper;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;

/**
 * FilteredAdapter is the filtered file adapter for Casbin.
 * It can load policy from a file or save policy to a file and
 * supports loading of filtered policies.
 *
 * @author tldyl
 * @since 2020/6/8
 */
public class FilteredAdapter implements org.casbin.jcasbin.persist.FilteredAdapter {
    private Adapter adapter;
    private boolean isFiltered = true;
    private String filepath;

    public FilteredAdapter(String filepath) {
        adapter = new FileAdapter(filepath);
        this.filepath = filepath;
    }

    /**
     * loadFilteredPolicy loads only policy rules that match the filter.
     * @param model the model.
     * @param filter the filter used to specify which type of policy should be loaded.
     * @throws CasbinAdapterException if the file path or the type of the filter is incorrect.
     */
    @Override
    public void loadFilteredPolicy(Model model, Object filter) throws CasbinAdapterException {
        if ("".equals(filepath)) {
            throw new CasbinAdapterException("Invalid file path, file path cannot be empty.");
        }
        if (filter == null) {
            adapter.loadPolicy(model);
            isFiltered = false;
            return;
        }
        if (!(filter instanceof Filter)) {
            throw new CasbinAdapterException("Invalid filter type.");
        }
        try {
            loadFilteredPolicyFile(model, (Filter) filter, Helper::loadPolicyLine);
            isFiltered = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * loadFilteredPolicyFile loads only policy rules that match the filter from file.
     */
    private void loadFilteredPolicyFile(Model model, Filter filter, Helper.loadPolicyLineHandler<String, Model> handler) throws CasbinAdapterException {
        try (FileInputStream fis = new FileInputStream(filepath)) {
            List<String> lines = IOUtils.readLines(fis, Charset.forName("UTF-8"));
            for (String line : lines) {
                line = line.trim();
                if (filterLine(line, filter)) {
                    continue;
                }
                handler.accept(line, model);
            }
        } catch (IOException e) {
            throw new CasbinAdapterException("Load policy file error", e.getCause());
        }
    }

    /**
     * match the line.
     */
    private boolean filterLine(String line, Filter filter) {
        if (filter == null) {
            return false;
        }
        String[] p = line.split(",");
        if (p.length == 0) {
            return true;
        }
        String[] filterSlice = null;
        switch (p[0].trim()) {
            case "p":
                filterSlice = filter.p;
                break;
            case "g":
                filterSlice = filter.g;
                break;
        }
        if (filterSlice == null) {
            filterSlice = new String[]{};
        }
        return filterWords(p, filterSlice);
    }

    /**
     * match the words in the specific line.
     */
    private boolean filterWords(String[] line, String[] filter) {
        if (line.length < filter.length + 1) {
            return true;
        }
        boolean skipLine = false;
        int i = 0;
        for (String s : filter) {
            i++;
            if (s.length() > 0 && !s.trim().equals(line[i].trim())) {
                skipLine = true;
                break;
            }
        }
        return skipLine;
    }

    /**
     * @return true if have any filter roles.
     */
    @Override
    public boolean isFiltered(){
        return isFiltered;
    }

    /**
     * loadPolicy loads all policy rules from the storage.
     */
    @Override
    public void loadPolicy(Model model) {
        adapter.loadPolicy(model);
        isFiltered = false;
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    @Override
    public void savePolicy(Model model) {
        adapter.savePolicy(model);
    }

    /**
     * addPolicy adds a policy rule to the storage.
     */
    @Override
    public void addPolicy(String sec, String ptype, List<String> rule) {
        adapter.addPolicy(sec, ptype, rule);
    }

    /**
     * removePolicy removes a policy rule from the storage.
     */
    @Override
    public void removePolicy(String sec, String ptype, List<String> rule) {
        adapter.removePolicy(sec, ptype, rule);
    }

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     */
    @Override
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        adapter.removeFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
    }

    /**
     * the filter class.
     * Enforcer only accept this filter currently.
     */
    public static class Filter {
        public String[] p;
        public String[] g;
    }
}
