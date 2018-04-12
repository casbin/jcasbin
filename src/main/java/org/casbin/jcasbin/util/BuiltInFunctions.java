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

import com.googlecode.aviator.runtime.function.AbstractFunction;
import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorFunction;
import com.googlecode.aviator.runtime.type.AviatorObject;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.casbin.jcasbin.rbac.RoleManager;

import java.util.Map;
import java.util.regex.Pattern;

public class BuiltInFunctions {
    /**
     * keyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*"
     */
    public static boolean keyMatch(String key1, String key2) {
        int i = key2.indexOf('*');
        if (i == -1) {
            return key1.equals(key2);
        }

        if (key1.length() > i) {
            return key1.substring(0, i).equals(key2.substring(0, i));
        }
        return key1.equals(key2.substring(0, i));
    }

    /**
     * keyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
     */
    public static boolean keyMatch2(String key1, String key2) {
        key2 = key2.replace("/*", "/.*");

        Pattern p = Pattern.compile("(.*):[^/]+(.*)");
        while (true) {
            if (!key2.contains("/:")) {
                break;
            }

            key2 = "^" + p.matcher(key2).replaceAll("$1[^/]+$2") + "$";
        }

        return regexMatch(key1, key2);
    }

    /**
     * keyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
     */
    public static boolean keyMatch3(String key1, String key2) {
        key2 = key2.replace("/*", "/.*");

        Pattern p = Pattern.compile("(.*)\\{[^/]+\\}(.*)");
        while (true) {
            if (!key2.contains("/{")) {
                break;
            }

            key2 = p.matcher(key2).replaceAll("$1[^/]+$2");
        }

        return regexMatch(key1, key2);
    }

    /**
     * regexMatch determines whether key1 matches the pattern of key2 in regular expression.
     */
    public static boolean regexMatch(String key1, String key2) {
        return Pattern.matches(key2, key1);
    }

    /**
     * ipMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
     * For example, "192.168.2.123" matches "192.168.2.0/24"
     */
    public static boolean ipMatch(String ip1, String ip2) {
        IPAddressString ipas1 = new IPAddressString(ip1);
        try {
            ipas1.validateIPv4();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new Error("invalid argument: ip1 in IPMatch() function is not an IP address.");
        }

        IPAddressString ipas2 = new IPAddressString(ip2);
        try {
            ipas2.validate();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new Error("invalid argument: ip2 in IPMatch() function is neither an IP address nor a CIDR.");
        }

        if (ipas1.equals(ipas2)) {
            return true;
        }

        IPAddress ipa1;
        IPAddress ipa2;
        try {
            ipa1 = ipas1.toAddress();
            ipa2 = ipas2.toAddress();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new Error("invalid argument: ip1 or ip2 in IPMatch() function is not an IP address.");
        }

        Integer prefix = ipa2.getNetworkPrefixLength();
        IPAddress mask = ipa2.getNetwork().getNetworkMask(prefix, false);
        return ipa1.mask(mask).equals(ipa2);
    }

    /**
     * generateGFunction is the factory method of the g(_, _) function.
     */
    public static AviatorFunction generateGFunction(RoleManager rm) {
        return new AbstractFunction() {
            public AviatorObject call(Map<String, Object> env, AviatorObject arg1, AviatorObject arg2) {
                String name1 = FunctionUtils.getStringValue(arg1, env);
                String name2 = FunctionUtils.getStringValue(arg2, env);

                if (rm == null) {
                    return AviatorBoolean.valueOf(name1.equals(name2));
                } else {
                    boolean res = rm.hasLink(name1, name2);
                    return AviatorBoolean.valueOf(res);
                }
            }

            public AviatorObject call(Map<String, Object> env, AviatorObject arg1, AviatorObject arg2, AviatorObject arg3) {
                String name1 = FunctionUtils.getStringValue(arg1, env);
                String name2 = FunctionUtils.getStringValue(arg2, env);

                if (rm == null) {
                    return AviatorBoolean.valueOf(name1.equals(name2));
                } else {
                    String domain = FunctionUtils.getStringValue(arg3, env);
                    boolean res = rm.hasLink(name1, name2, domain);
                    return AviatorBoolean.valueOf(res);
                }
            }

            public String getName() {
                return "g";
            }
        };
    }
}
