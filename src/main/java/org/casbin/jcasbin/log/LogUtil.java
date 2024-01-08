package org.casbin.jcasbin.log;

import java.util.Map;

public class LogUtil {
    private static Logger logger = new DefaultLogger();

    public static void setLogger(Logger l) {
        logger = l;
    }

    public static Logger getLogger() {
        return logger;
    }

    public static void logModel(String[][] model) {
        logger.logModel(model);
    }

    public static void logEnforce(String matcher, Object[] request, boolean result, String[][] explains) {
        logger.logEnforce(matcher, request, result, explains);
    }

    public static void logRole(String[] roles) {
        logger.logRole(roles);
    }

    public static void logPolicy(Map<String, String[][]> policy) {
        logger.logPolicy(policy);
    }

    public static void logError(Throwable err, String... msg) {
        logger.logError(err, msg);
    }
}
