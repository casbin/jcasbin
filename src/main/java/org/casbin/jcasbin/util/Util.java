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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Util {
    public static boolean enableLog = true;
    private static Pattern evalReg = Pattern.compile("\\beval\\(([^),]*)\\)");

    private static Logger LOGGER = LoggerFactory.getLogger("org.casbin.jcasbin");

    /**
     * logPrint prints the log.
     *
     * @param v the log.
     */
    public static void logPrint(String v) {
        if (enableLog) {
            LOGGER.info(v);
        }
    }

    /**
     * logPrintf prints the log with the format.
     *
     * @param format the format of the log.
     * @param v the log.
     */
    public static void logPrintf(String format, String... v) {
        if (enableLog) {
            String tmp = String.format(format, (Object[]) v);
            LOGGER.info(tmp);
        }
    }

    /**
     * logPrintf prints the log with the format as a warning.
     *
     * @param format the format of the log.
     * @param v the log.
     */
    public static void logPrintfWarn(String format, Object... v) {
        if (enableLog) {
            LOGGER.warn(format, v);
        }
    }

    /**
     * logPrintf prints the log with the format as an error.
     *
     * @param format the format of the log.
     * @param v the log.
     */
    public static void logPrintfError(String format, Object... v) {
        if (enableLog) {
            LOGGER.error(format, v);
        }
    }

    /**
     * escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
     *
     * @param s the value of the matcher and effect assertions.
     * @return the escaped value.
     */
    public static String escapeAssertion(String s) {
        //Replace the first dot, because the string doesn't start with "m="
        // and is not covered by the regex.
        if (s.startsWith("r") || s.startsWith("p")) {
            s = s.replaceFirst("\\.", "_");
        }
        String regex = "(\\|| |=|\\)|\\(|&|<|>|,|\\+|-|!|\\*|\\/)(r|p)\\.";
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(s);
        StringBuffer sb = new StringBuffer();

        while (m.find()) {
            m.appendReplacement(sb, m.group().replace(".", "_") );
        }

        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * removeComments removes the comments starting with # in the text.
     *
     * @param s a line in the model.
     * @return the line without comments.
     */
    public static String removeComments(String s) {
        int pos = s.indexOf("#");
        if (pos == -1) {
            return s;
        }
        return s.substring(0,pos).trim();
    }

    /**
     * arrayEquals determines whether two string arrays are identical.
     *
     * @param a the first array.
     * @param b the second array.
     * @return whether a equals to b.
     */
    public static boolean arrayEquals(List<String> a, List<String> b) {
        if (a == null) {
            a = new ArrayList<>();
        }
        if (b == null) {
            b = new ArrayList<>();
        }
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
     *
     * @param a the first 2-dimensional array.
     * @param b the second 2-dimensional array.
     * @return whether a equals to b.
     */
    public static boolean array2DEquals(List<List<String>> a, List<List<String>> b) {
        if (a == null) {
            a = new ArrayList<>();
        }
        if (b == null) {
            b = new ArrayList<>();
        }
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
     *
     * @param s the array.
     * @return the array without duplicates.
     */
    public static boolean arrayRemoveDuplicates(List<String> s) {
        return true;
    }

    /**
     * arrayToString gets a printable string for a string array.
     *
     * @param s the array.
     * @return the string joined by the array elements.
     */
    public static String arrayToString(List<String> s) {
        return String.join(", ", s);
    }

    /**
     * paramsToString gets a printable string for variable number of parameters.
     *
     * @param s the parameters.
     * @return the string joined by the parameters.
     */
    public static String paramsToString(String[] s) {
        return String.join(", ", s);
    }

    /**
     * splitCommaDelimited splits a comma-delimited string into a string array. It assumes that any
     * number of whitespace might exist before or after the comma and that tokens do not include
     * whitespace as part of their value.
     *
     * @param s the comma-delimited string.
     * @return the array with the string tokens.
     */
    public static String[] splitCommaDelimited(String s) {
        if (s == null) {
            return null;
        }
        return s.trim().split("\\s*,\\s*");
    }

    /**
     * setEquals determines whether two string sets are identical.
     *
     * @param a the first set.
     * @param b the second set.
     * @return whether a equals to b.
     */
    public static boolean setEquals(List<String> a, List<String> b) {
        if (a == null) {
            a = new ArrayList<>();
        }
        if (b == null) {
            b = new ArrayList<>();
        }
        if (a.size() != b.size()) {
            return false;
        }

        Collections.sort(a);
        Collections.sort(b);

        for (int i = 0; i < a.size(); i ++) {
            if (!a.get(i).equals(b.get(i))) {
                return false;
            }
        }
        return true;
    }

    public static boolean hasEval(String exp) {
        return evalReg.matcher(exp).matches();
    }

    public static String replaceEval(String s, String replacement) {
        return evalReg.matcher(s).replaceAll("(" + replacement + ")");
    }
}
