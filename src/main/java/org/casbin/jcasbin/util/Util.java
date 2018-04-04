package org.casbin.jcasbin.util;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Util {
    static boolean enableLog = true;

    static Logger logger = Logger.getLogger("casbin");

    /**
     * logPrint prints the log.
     */
    public static void logPrint(String v) {
        if (enableLog) {
            logger.log(Level.INFO, v);
        }
    }

    /**
     * logPrintf prints the log with the format.
     */
    public static void logPrintf(String format, String... v) {
        if (enableLog) {
            String tmp = String.format(format, (Object[]) v);
            logger.log(Level.INFO, tmp);
        }
    }

    /**
     * escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
     */
    public static String escapeAssertion(String s) {
        s = s.replaceAll("r.", "r_");
        s = s.replaceAll("p.", "p_");
        return s;
    }

    /**
     * removeComments removes the comments starting with # in the text.
     */
    public static String removeComments(String s) {
        return s;
    }
}
