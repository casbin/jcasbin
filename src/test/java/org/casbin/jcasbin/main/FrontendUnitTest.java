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
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;

public class FrontendUnitTest {

  @Test
  public void testCasbinJsGetPermissionForUser() throws IOException {
    SyncedEnforcer e = new SyncedEnforcer("examples/rbac_model.conf", "examples/rbac_with_hierarchy_policy.csv");
    HashMap<String, Object> received = new Gson().fromJson(Frontend.casbinJsGetPermissionForUser(e, "alice"), HashMap.class);
    String receivedModelStr = ((String) received.get("m")).replace("\r\n", "\n").replace("\r", "\n");
    String expectedModelStr = new String(Files.readAllBytes(Paths.get("examples/rbac_model.conf"))).replace("\r\n", "\n").replace("\r", "\n");
    assertEquals(expectedModelStr, receivedModelStr);

    String expectedPolicyStr = new String(Files.readAllBytes(Paths.get("examples/rbac_with_hierarchy_policy.csv"))).replace("\r\n", "\n").replace("\r", "\n");
    expectedPolicyStr = Pattern.compile("\n+").matcher(expectedPolicyStr).replaceAll("\n");
    String[] expectedPolicyItem = expectedPolicyStr.split(",|\n");
    int i = 0;
    for (List<String> sArr : (List<List<String>>) received.get("p")) {
      for (String s : sArr) {
        assertEquals(expectedPolicyItem[i].trim(), s.trim());
        i++;
      }
    }
    for (List<String> sArr : (List<List<String>>) received.get("g")) {
      for (String s : sArr) {
        assertEquals(expectedPolicyItem[i].trim(), s.trim());
        i++;
      }
    }
  }
}
