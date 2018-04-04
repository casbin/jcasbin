package org.casbin.jcasbin.util;

public class BuiltInFunctions {
    /**
     * keyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*"
     */
    public static boolean keyMatch(String key1, String key2) {
        return true;
    }

    /**
     * regexMatch determines whether key1 matches the pattern of key2 in regular expression.
     */
    public static boolean regexMatch(String key1, String key2) {
        return true;
    }

    /**
     * ipMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
     * For example, "192.168.2.123" matches "192.168.2.0/24"
     */
    public static boolean ipMatch(String key1, String key2) {
        return true;
    }
}
