package org.casbin.jcasbin.persist;

import java.util.List;

/**
 * UpdatableAdapter is the interface for Casbin adapters with add update policy function.
 * @author canxer314
 */
public interface UpdatableAdapter extends Adapter{

    /**
     * UpdatePolicy updates a policy rule from storage.
     * This is part of the Auto-Save feature.
     * @param sec
     * @param ptype
     * @param oldRule
     * @param newPolicy
     */
    void updatePolicy(String sec, String ptype, List<String> oldRule, List<String> newPolicy);
}
