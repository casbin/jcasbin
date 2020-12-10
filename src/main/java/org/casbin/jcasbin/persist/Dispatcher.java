package org.casbin.jcasbin.persist;

import java.util.List;

/**
 * Dispatcher is the interface for jCasbin dispatcher
 *
 * @author canxer314
 */
public interface Dispatcher {
    /**
     * // AddPolicies adds policies rule to all instance.
     *
     * @param sec
     * @param ptype
     * @param rules
     */
    void addPolicies(String sec, String ptype, List<List<String>> rules);

    /**
     * RemovePolicies removes policies rule from all instance.
     *
     * @param sec
     * @param ptype
     * @param rules
     */
    void removePolicies(String sec, String ptype, List<List<String>> rules);

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from all instance.
     *
     * @param sec
     * @param ptype
     * @param fieldIndex
     * @param fieldValues
     */
    void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues);

    /**
     * ClearPolicy clears all current policy in all instances
     */
    void clearPolicy();

    /**
     * UpdatePolicy updates policy rule from all instance.
     *
     * @param sec
     * @param ptype
     * @param oldRule
     * @param newRule
     */
    void updatePolicy(String sec, String ptype, List<String> oldRule, List<String> newRule);
}
