// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.jcasbin.util;

import java.util.List;
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

    /**
     * arrayEquals determines whether two string arrays are identical.
     */
    public static boolean arrayEquals(List<String> a, List<String> b) {
        if (a.size() != b.size()) {
            return false;
        }

        for (int i = 0; i < a.size(); i ++) {
            if (!a.get(i).equals(b.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * array2DEquals determines whether two 2-dimensional string arrays are identical.
     */
    public static boolean array2DEquals(List<List<String>> a, List<List<String>> b) {
        if (a.size() != b.size()) {
            return false;
        }

        for (int i = 0; i < a.size(); i ++) {
            if (!arrayEquals(a.get(i), b.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * arrayRemoveDuplicates removes any duplicated elements in a string array.
     */
    public static boolean arrayRemoveDuplicates(List<String> s) {
        return true;
    }

    /**
     * arrayToString gets a printable string for a string array.
     */
    public static String arrayToString(List<String> s) {
        return String.join(", ", s);
    }
}
