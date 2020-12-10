package org.casbin.jcasbin.persist;

import java.util.List;

/**
 * WatcherUpdatable is the strengthen for jCasbin watchers.
 *
 * @author canxer314
 */
public interface WatcherUpdatable extends Watcher {

    /**
     * updateForUpdatePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after Enforcer.UpdatePolicy()
     *
     * @param oldRule
     * @param newRule
     */
    void updateForUpdatePolicy(List<String> oldRule, List<String> newRule);
}
