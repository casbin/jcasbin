// Copyright 2024 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.log.LogUtil;
import org.casbin.jcasbin.log.mocks.MockLogger;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.Map;

public class LogUtilTest {

    @Test
    public void testLogUtil() {
        MockLogger mockLogger = Mockito.mock(MockLogger.class);

        LogUtil.setLogger(mockLogger);

        Mockito.when(mockLogger.isEnabled()).thenReturn(true);

        LogUtil.logModel(new String[][]{{"data1", "data2"}});
        LogUtil.logEnforce("matcher", new Object[]{"request"}, true, new String[][]{{"explain1", "explain2"}});
        LogUtil.logRole(new String[]{"role1", "role2"});

        Map<String, String[][]> policy = new HashMap<>();
        policy.put("key1", new String[][]{{"value1"}});
        policy.put("key2", new String[][]{{"value2"}});

        LogUtil.logPolicy(policy);
        LogUtil.logError(new RuntimeException("Test Error"), "Error Message");

        Mockito.verify(mockLogger).logModel(ArgumentMatchers.eq(new String[][]{{"data1", "data2"}}));
        Mockito.verify(mockLogger).logEnforce(
            ArgumentMatchers.eq("matcher"),
            ArgumentMatchers.eq(new Object[]{"request"}),
            ArgumentMatchers.eq(true),
            ArgumentMatchers.eq(new String[][]{{"explain1", "explain2"}})
        );
        Mockito.verify(mockLogger).logRole(ArgumentMatchers.eq(new String[]{"role1", "role2"}));
        Mockito.verify(mockLogger).logPolicy(ArgumentMatchers.eq(policy));
        Mockito.verify(mockLogger).logError(
            Mockito.any(RuntimeException.class),
            ArgumentMatchers.eq("Error Message")
        );
    }
}
