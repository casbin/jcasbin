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

public class Config {
    public static Config newConfig(String confName) {
        Config cfg = new Config();
        return cfg;
    }

    public static Config newConfigFromText(String confName) {
        Config cfg = new Config();
        return cfg;
    }

    public boolean addConfig(String section, String option, String value) {
        return true;
    }

    private void parse(String fname) {

    }

    public boolean getBool(String key) {
        return true;
    }

    public int getInt(String key) {
        return 0;
    }

    public float getFloat(String key) {
        return 0;
    }

    public String getString(String key) {
        return "";
    }

    public String[] getStrings(String key) {
        return new String[]{};
    }
}
