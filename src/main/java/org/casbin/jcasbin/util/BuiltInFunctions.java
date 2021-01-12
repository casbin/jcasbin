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

import bsh.EvalError;
import bsh.Interpreter;
import com.googlecode.aviator.runtime.function.AbstractFunction;
import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorFunction;
import com.googlecode.aviator.runtime.type.AviatorObject;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import org.casbin.jcasbin.rbac.RoleManager;

import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BuiltInFunctions {

    private static Pattern keyMatch2Pattern = Pattern.compile("(.*):[^/]+(.*)");
    private static Pattern keyMatch3Pattern = Pattern.compile("(.*)\\{[^/]+}(.*)");

    private static final Interpreter interpreter;

    static {
        interpreter = new Interpreter();
    }

    /**
     * keyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *.
     *
     * <pre>
     * For example, "/foo/bar" matches "/foo/*"
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
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
     * keyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *.
     *
     * <pre>
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch2(String key1, String key2) {
        key2 = key2.replace("/*", "/.*");
        while (key2.contains("/:")) {
            key2 = "^" + keyMatch2Pattern.matcher(key2).replaceAll("$1[^/]+$2") + "$";
        }

        return regexMatch(key1, key2);
    }

    /**
     * keyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *.
     *
     * <pre>
     * For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch3(String key1, String key2) {
        key2 = key2.replace("/*", "/.*");

        while (key2.contains("/{")) {
            key2 = keyMatch3Pattern.matcher(key2).replaceAll("$1[^/]+$2");
        }

        return regexMatch(key1, key2);
    }

    /**
     * KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2
     * can contain a *. Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
     *
     * <pre>
     * "/parent/123/child/123" matches "/parent/{id}/child/{id}"
     * "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
     * But KeyMatch3 will match both.
     * </pre>
     *
     * Attention: key1 cannot contain English commas.
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean keyMatch4(String key1, String key2) {
        String regEx = "\\{[^/]+}";
        Pattern p = Pattern.compile(regEx);
        Matcher m = p.matcher(key2);

        String[] tmp = p.split(key2);
        List<String> tokens = new ArrayList<>();
        if (tmp.length > 0) {
            int count = 0;
            while (count < tmp.length) {
                tokens.add(tmp[count]);
                if (m.find()) {
                    tokens.add(m.group());
                }
                count++;
            }
        }
        int off = 0;
        for (String token : tokens) {
            if (!p.matcher(token).matches()) {
                while (off < key1.length() && key1.charAt(off) != token.charAt(0)) {
                    off++;
                }
                if (key1.length() - (off + 1) < token.length()) {
                    return false;
                }
                if (!key1.substring(off, off + token.length()).equals(token)) {
                    return false;
                }
                key1 = key1.replaceFirst(token, ",");
            }
        }
        String[] values = key1.split(",");
        int i = 0;
        Map<String, String> params = new HashMap<>();
        for (String token : tokens) {
            if (p.matcher(token).matches()) {
                while (i < values.length && values[i].equals("")) {
                    i++;
                }
                if (i == values.length) {
                    return false;
                }
                if (params.containsKey(token)) {
                    if (!values[i].equals(params.get(token))) {
                        return false;
                    }
                } else {
                    params.put(token, values[i]);
                }
                i++;
            }
        }
        return true;
    }

    /**
     * regexMatch determines whether key1 matches the pattern of key2 in regular expression.
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean regexMatch(String key1, String key2) {
        return Pattern.matches(key2, key1);
    }

    /**
     * ipMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be
     * an IP address or a CIDR pattern. For example, "192.168.2.123" matches "192.168.2.0/24"
     *
     * @param ip1 the first argument.
     * @param ip2 the second argument.
     * @return whether ip1 matches ip2.
     */
    public static boolean ipMatch(String ip1, String ip2) {
        IPAddressString ipas1 = new IPAddressString(ip1);
        try {
            ipas1.validateIPv4();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");
        }

        IPAddressString ipas2 = new IPAddressString(ip2);
        try {
            ipas2.validate();
        } catch (AddressStringException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("invalid argument: ip2 in IPMatch() function is neither an IP address nor a CIDR.");
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
            throw new IllegalArgumentException("invalid argument: ip1 or ip2 in IPMatch() function is not an IP address.");
        }

        Integer prefix = ipa2.getNetworkPrefixLength();
        IPAddress mask = ipa2.getNetwork().getNetworkMask(prefix, false);
        return ipa1.mask(mask).equals(ipas2.getHostAddress());
    }

    /**
     * globMatch determines whether key1 matches the pattern of key2 in glob expression.
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean globMatch(String key1, String key2) {
        return Pattern.matches(Glob.toRegexPattern(key2), key1);
    }

    /**
     * allMatch determines whether key1 matches the pattern of key2 , key2 can contain a *.
     *
     * <pre>
     * For example, "*" matches everything
     * </pre>
     *
     * @param key1 the first argument.
     * @param key2 the second argument.
     * @return whether key1 matches key2.
     */
    public static boolean allMatch(String key1, String key2) {
        if ("*".equals(key1) || "*".equals(key2)) {
            return true;
        }

        return key1.equals(key2);
    }

    /**
     * generateGFunction is the factory method of the g(_, _) function.
     *
     * @param name the name of the g(_, _) function, can be "g", "g2", ..
     * @param rm the role manager used by the function.
     * @return the function.
     */
    public static AviatorFunction generateGFunction(String name, RoleManager rm) {
        return new AbstractFunction() {
            @Override
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

            @Override
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

            @Override
            public String getName() {
                return name;
            }
        };
    }

    /**
     * eval calculates the stringified boolean expression and return its result. The syntax of
     * expressions is exactly the same as Java. Flaw: dynamically generated classes or non-static
     * inner class cannot be used.
     *
     * @author tldyl
     * @since 2020-07-02
     *
     * @param eval Boolean expression.
     * @param env Parameters.
     * @return The result of the eval.
     */
    public static boolean eval(String eval, Map<String, Object> env) {
        Map<String, Map<String, Object>> evalModels = getEvalModels(env);
        try {
            for (final Entry<String, Map<String, Object>> entry : evalModels.entrySet()) {
                // String key
                interpreter.set(entry.getKey(), entry.getValue());
            }

            List<String> sortedSrc = new ArrayList<>(getReplaceTargets(evalModels));
            sortedSrc.sort((o1, o2) -> o1.length() > o2.length() ? -1 : 1);
            for (String s : sortedSrc) {
                eval = eval.replace("." + s, ".get(\"" + s + "\")");
            }
            return (boolean) interpreter.eval(eval);
        } catch (EvalError evalError) {
            evalError.printStackTrace();
        }
        return false;
    }

    /**
     * getEvalModels extracts the value from env and assemble it into a EvalModel object.
     *
     * @param env the map.
     */
    private static Map<String, Map<String, Object>> getEvalModels(Map<String, Object> env) {
        final Map<String, Map<String, Object>> evalModels = new HashMap<>();
        for (final Entry<String, Object> entry : env.entrySet()) {
            final String[] names = entry.getKey().split("_");
            evalModels.computeIfAbsent(names[0], k -> new HashMap<>()).put(names[1], entry.getValue());
        }
        return evalModels;
    }

    private static Set<String> getReplaceTargets(Map<String, Map<String, Object>> evalModels) {
        Set<String> ret = new HashSet<>();
        for (final Entry<String, Map<String, Object>> entry : evalModels.entrySet()) {
            ret.addAll(entry.getValue().keySet());
        }
        return ret;
    }
}
