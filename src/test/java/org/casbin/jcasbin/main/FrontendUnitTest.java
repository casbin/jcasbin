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

import com.google.gson.Gson;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;

public class FrontendUnitTest {

    @Test
    public void testCasbinJsGetPermissionForUser() throws IOException {
        SyncedEnforcer e = new SyncedEnforcer("examples/rbac_model.conf", "examples/rbac_with_hierarchy_policy.csv");
        HashMap<String, Object> received = new Gson().fromJson(Frontend.casbinJsGetPermissionForUser(e, "alice"), HashMap.class);

        String expectedModelStr = new String(Files.readAllBytes(Paths.get("examples/rbac_model.conf")));
        assertEquals(normalizeLineSeparators((String) received.get("m")), normalizeLineSeparators(expectedModelStr));

        assertEquals(
            received.get("p"),
            asList(
                asList("p", "alice", "data1", "read"),
                asList("p", "bob", "data2", "write"),
                asList("p", "data1_admin", "data1", "read"),
                asList("p", "data1_admin", "data1", "write"),
                asList("p", "data2_admin", "data2", "read"),
                asList("p", "data2_admin", "data2", "write")
            )
        );

        assertEquals(
            received.get("g"),
            asList(
                asList("g", "alice", "admin"),
                asList("g", "admin", "data1_admin"),
                asList("g", "admin", "data2_admin")
            )
        );

    }

    private static String normalizeLineSeparators(String text) {
        // 替换所有类型的行分隔符为 \n
        return text.replaceAll("\r\n|\r|\n", "\n");
    }
}
