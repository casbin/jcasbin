package org.casbin.jcasbin.persist;

import java.util.List;

/**
 * BatchAdapter is the interface for Casbin adapters with multiple add and remove policy functions.
 *
 * @author hsluoyz, canxer314
 */
public interface BatchAdapter extends Adapter {
    /**
     * AddPolicies adds policy rules to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec
     * @param ptype
     * @param rules
     */
    void addPolicies(String sec, String ptype, List<List<String>> rules);

    /**
     * RemovePolicies removes policy rules from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec
     * @param ptype
     * @param rules
     */
    void removePolicies(String sec, String ptype, List<List<String>> rules);
}
