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

package org.casbin.jcasbin.main;

import org.junit.Test;
import static org.casbin.jcasbin.main.TestUtil.testGlobMatch;

public class BuiltInFunctionsUnitTest {

    @Test
    public void testGlobMatchFunc() {
        testGlobMatch("/foo", "/foo", true);
        testGlobMatch("/foo", "/foo*", true);
        testGlobMatch("/foo", "/foo/*", false);
        testGlobMatch("/foo/bar", "/foo", false);
        testGlobMatch("/foo/bar", "/foo*", false);
        testGlobMatch("/foo/bar", "/foo/*", true);
        testGlobMatch("/foobar", "/foo", false);
        testGlobMatch("/foobar", "/foo*", true);
        testGlobMatch("/foobar", "/foo/*", false);

        testGlobMatch("/foo", "*/foo", true);
        testGlobMatch("/foo", "*/foo*", true);
        testGlobMatch("/foo", "*/foo/*", false);
        testGlobMatch("/foo/bar", "*/foo", false);
        testGlobMatch("/foo/bar", "*/foo*", false);
        testGlobMatch("/foo/bar", "*/foo/*", true);
        testGlobMatch("/foobar", "*/foo", false);
        testGlobMatch("/foobar", "*/foo*", true);
        testGlobMatch("/foobar", "*/foo/*", false);

        testGlobMatch("/prefix/foo", "*/foo", false);
        testGlobMatch("/prefix/foo", "*/foo*", false);
        testGlobMatch("/prefix/foo", "*/foo/*", false);
        testGlobMatch("/prefix/foo/bar", "*/foo", false);
        testGlobMatch("/prefix/foo/bar", "*/foo*", false);
        testGlobMatch("/prefix/foo/bar", "*/foo/*", false);
        testGlobMatch("/prefix/foobar", "*/foo", false);
        testGlobMatch("/prefix/foobar", "*/foo*", false);
        testGlobMatch("/prefix/foobar", "*/foo/*", false);

        testGlobMatch("/prefix/subprefix/foo", "*/foo", false);
        testGlobMatch("/prefix/subprefix/foo", "*/foo*", false);
        testGlobMatch("/prefix/subprefix/foo", "*/foo/*", false);
        testGlobMatch("/prefix/subprefix/foo/bar", "*/foo", false);
        testGlobMatch("/prefix/subprefix/foo/bar", "*/foo*", false);
        testGlobMatch("/prefix/subprefix/foo/bar", "*/foo/*", false);
        testGlobMatch("/prefix/subprefix/foobar", "*/foo", false);
        testGlobMatch("/prefix/subprefix/foobar", "*/foo*", false);
        testGlobMatch("/prefix/subprefix/foobar", "*/foo/*", false);
    }
}
