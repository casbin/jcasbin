// Copyright 2017 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.config;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class Config {
    private static final String DEFAULT_SECTION = "default";
    private static final String DEFAULT_COMMENT = "#";
    private static final String DEFAULT_COMMENT_SEM = ";";

    private ReentrantLock lock = new ReentrantLock();

    // Section:key=value
    private Map<String, Map<String, String>> data;

    /**
     * newConfig create an empty configuration representation from file.
     */
    public static Config newConfig(String confName) {
        Config c = new Config();
        c.parse(confName);
        return c;
    }

    /**
     * newConfigFromText create an empty configuration representation from text.
     */
    public static Config newConfigFromText(String text) {
        Config c = new Config();
        c.parseBuffer(new BufferedReader(new StringReader(text)));
        return c;
    }

    /**
     * addConfig adds a new section->key:value to the configuration.
     */
    public boolean addConfig(String section, String option, String value) {
        if (section.equals("")) {
            section = DEFAULT_SECTION;
        }

        if (!data.containsKey(section)) {
            data.put(section, new HashMap<>());
        }

        boolean ok = data.get(section).containsKey(option);
        data.get(section).put(option, value);
        return !ok;
    }

    private void parse(String fname) {
        lock.lock();
        FileInputStream fis;
        try {
            fis = new FileInputStream(fname);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new Error("model file not found");
        }

        BufferedReader buf = new BufferedReader(new InputStreamReader(fis));
        parseBuffer(buf);
        lock.unlock();
        try {
            fis.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("IO error occurred");
        }
    }

    private void parseBuffer(BufferedReader buf) {
        String section = "";
        int lineNum = 0;
        String line;

        while (true) {
            lineNum ++;
            try {
                if ((line = buf.readLine()) != null) {
                    if (line.equals("")) {
                        continue;
                    }
                } else {
                    break;
                }
            } catch (IOException e) {
                e.printStackTrace();
                throw new Error("IO error occurred");
            }

            line = line.trim();
            if (line.startsWith(DEFAULT_COMMENT)) {
                continue;
            } else if (line.startsWith(DEFAULT_COMMENT_SEM)) {
                continue;
            } else if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length() - 1);
            } else {
                String[] optionVal = line.split("=", 2);
                if (optionVal.length != 2) {
                    throw new Error(String.format("parse the content error : line %d , %s = ? ", lineNum, optionVal[0]));
                }
                String option = optionVal[0].trim();
                String value = optionVal[1].trim();
                addConfig(section, option, value);
            }
        }
    }

    public boolean getBool(String key) {
        return Boolean.parseBoolean(get(key));
    }

    public int getInt(String key) {
        return Integer.parseInt(get(key));
    }

    public float getFloat(String key) {
        return Float.parseFloat(get(key));
    }

    public String getString(String key) {
        return get(key);
    }

    public String[] getStrings(String key) {
        String v = get(key);
        if (v.equals("")) {
            return null;
        }
        return v.split(",");
    }

    public void set(String key, String value) {
        lock.lock();
        if (key.length() == 0) {
            throw new Error("key is empty");
        }

        String section = "";
        String option;

        String[] keys = key.toLowerCase().split("::");
        if (keys.length >= 2) {
            section = keys[0];
            option = keys[1];
        } else {
            option = keys[0];
        }

        addConfig(section, option, value);
    }

    public String get(String key) {
        String section;
        String option;

        String[] keys = key.toLowerCase().split("::");
        if (keys.length >= 2) {
            section = keys[0];
            option = keys[1];
        } else {
            section = DEFAULT_SECTION;
            option = keys[0];
        }

        boolean ok = data.get(section).containsKey(option);
        if (ok) {
            return data.get(section).get(option);
        } else {
            return "";
        }
    }
}
