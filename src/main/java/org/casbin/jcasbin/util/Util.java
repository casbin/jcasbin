package org.casbin.jcasbin.util;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Util {
    static boolean enableLog = true;

    static Logger logger = Logger.getLogger("casbin");

    public static void logPrint(String v) {
        if (enableLog) {
            logger.log(Level.INFO, v);
        }
    }

    public static void logPrintf(String format, String... v) {
        if (enableLog) {
            String tmp = String.format(format, v);
            logger.log(Level.INFO, tmp);
        }
    }
}
