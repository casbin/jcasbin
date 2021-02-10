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
import static org.casbin.jcasbin.main.TestUtil.testKeyGet;
import static org.casbin.jcasbin.main.TestUtil.testKeyGet2;

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

    @Test
    public void testKeyGetFunc() {
        testKeyGet("/foo", "/foo", "");
        testKeyGet("/foo", "/foo*", "");
        testKeyGet("/foo", "/foo/*", "");
        testKeyGet("/foo/bar", "/foo", "");
        testKeyGet("/foo/bar", "/foo*", "/bar");
        testKeyGet("/foo/bar", "/foo/*", "bar");
        testKeyGet("/foobar", "/foo", "");
        testKeyGet("/foobar", "/foo*", "bar");
        testKeyGet("/foobar", "/foo/*", "");
    }

    @Test
    public void TestKeyGet2() {
        testKeyGet2("/foo", "/foo", "id", "");
        testKeyGet2("/foo", "/foo*", "id", "");
        testKeyGet2("/foo", "/foo/*", "id", "");
        testKeyGet2("/foo/bar", "/foo", "id", "");
        // different with KeyMatch.
        testKeyGet2("/foo/bar", "/foo*", "id", "");
        testKeyGet2("/foo/bar", "/foo/*", "id", "");
        testKeyGet2("/foobar", "/foo", "id", "");
        // different with KeyMatch.
        testKeyGet2("/foobar", "/foo*", "id", "");
        testKeyGet2("/foobar", "/foo/*", "id", "");

        testKeyGet2("/", "/:resource", "resource", "");
        testKeyGet2("/resource1", "/:resource", "resource", "resource1");
        testKeyGet2("/myid", "/:id/using/:resId", "id", "");
        testKeyGet2("/myid/using/myresid", "/:id/using/:resId", "id", "myid");
        testKeyGet2("/myid/using/myresid", "/:id/using/:resId", "resId", "myresid");

        testKeyGet2("/proxy/myid", "/proxy/:id/*", "id", "");
        testKeyGet2("/proxy/myid/", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res/res2", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res/res2/res3", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id", "myid");
        testKeyGet2("/proxy/", "/proxy/:id/*", "id", "");

        testKeyGet2("/alice", "/:id", "id", "alice");
        testKeyGet2("/alice/all", "/:id/all", "id", "alice");
        testKeyGet2("/alice", "/:id/all", "id", "");
        testKeyGet2("/alice/all", "/:id", "id", "");
        testKeyGet2("/alice/all", "/:/all", "", "");
    }
}
