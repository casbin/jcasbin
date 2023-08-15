// Copyright 2021 The casbin Authors. All Rights Reserved.
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

/**
 * @author Yixiang Zhao (@seriouszyx)
 * @description EnforceContext is used as the first element of the parameter "rvals" in method "enforce"
 * @date 2021-11-30 18:56
 **/
public class EnforceContext {

    private String pType;
    private String eType;
    private String mType;
    private String rType;

    public EnforceContext(String suffix) {
        this.pType = "p" + suffix;
        this.eType = "e" + suffix;
        this.mType = "m" + suffix;
        this.rType = "r" + suffix;
    }

    public EnforceContext(String pSuffix, String eSuffix, String mSuffix, String rSuffix) {
        this.pType = "p" + pSuffix;
        this.eType = "e" + eSuffix;
        this.mType = "m" + mSuffix;
        this.rType = "r" + rSuffix;
    }

    public String getpType() {
        return pType;
    }

    public void setpType(String pType) {
        this.pType = pType;
    }

    public String geteType() {
        return eType;
    }

    public void seteType(String eType) {
        this.eType = eType;
    }

    public String getmType() {
        return mType;
    }

    public void setmType(String mType) {
        this.mType = mType;
    }

    public String getrType() {
        return rType;
    }

    public void setrType(String rType) {
        this.rType = rType;
    }
}
