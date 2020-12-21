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
