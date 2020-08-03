package org.casbin.jcasbin.persist;

import java.util.List;

public interface BatchAdapter extends Adapter {
    void addPolicies(String sec, String ptype, List<List<String>> rules);

    void removePolicies(String sec, String ptype, List<List<String>> rules);
}
