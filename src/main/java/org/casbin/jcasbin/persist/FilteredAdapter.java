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

package org.casbin.jcasbin.persist;

import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.model.Model;

/**
 * FilteredAdapter is the interface for Casbin adapters supporting filtered policies.
 *
 * @author shy
 * @since 2020/12/21
 */
public interface FilteredAdapter extends Adapter {

    /**
     * loadFilteredPolicy loads only policy rules that match the filter.
     * @param model the model.
     * @param filter the filter used to specify which type of policy should be loaded.
     * @throws CasbinAdapterException if the file path or the type of the filter is incorrect.
     */
    void loadFilteredPolicy(Model model, Object filter) throws CasbinAdapterException;

    /**
     * IsFiltered returns true if the loaded policy has been filtered.
     * @return true if have any filter roles.
     */
    boolean isFiltered();
}
