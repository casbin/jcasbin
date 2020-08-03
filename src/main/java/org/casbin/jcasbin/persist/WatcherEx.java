package org.casbin.jcasbin.persist;

import org.casbin.jcasbin.model.Model;

public interface WatcherEx extends Watcher {
    void updateForAddPolicy(String... params);

    void updateForRemovePolicy(String... params);

    void updateForRemoveFilteredPolicy(int fieldIndex, String... fieldValues);

    void updateForSavePolicy(Model model);
}
