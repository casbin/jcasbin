package org.casbin.jcasbin.log;

import java.util.Map;

public interface Logger {
    void enableLog(boolean enable);

    boolean isEnabled();

    void logModel(String[][] model);

    void logEnforce(String matcher, Object[] request, boolean result, String[][] explains);

    void logRole(String[] roles);

    void logPolicy(Map<String, String[][]> policy);

    void logError(Throwable err, String... msg);
}
