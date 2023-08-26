// Copyright 2020 The casbin Authors. All Rights Reserved.
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

import org.casbin.jcasbin.util.SyncedLRUCache;
import org.casbin.jcasbin.util.Util;
import org.junit.Test;

import static org.junit.Assert.*;

public class UtilTest {

  @Test
  public void testEscapeAssertion(){
      assertEquals("r_sub == r_obj.value", Util.escapeAssertion("r_sub == r_obj.value"));
      assertEquals("p_sub == r_sub.value", Util.escapeAssertion("p_sub == r_sub.value"));
      assertEquals("r_attr.value == p_attr", Util.escapeAssertion("r.attr.value == p.attr"));
      assertEquals("r2_attr.value == p2_attr", Util.escapeAssertion("r2.attr.value == p2.attr"));
      assertEquals("r_attr.value == p_attr", Util.escapeAssertion("r.attr.value == p.attr"));
      assertEquals("r_attp.value || p_attr", Util.escapeAssertion("r.attp.value || p.attr"));
      assertEquals("r_attp.value &&p_attr", Util.escapeAssertion("r.attp.value &&p.attr"));
      assertEquals("r_attp.value >p_attr", Util.escapeAssertion("r.attp.value >p.attr"));
      assertEquals("r_attp.value <p_attr", Util.escapeAssertion("r.attp.value <p.attr"));
      assertEquals("r_attp.value -p_attr", Util.escapeAssertion("r.attp.value -p.attr"));
      assertEquals("r_attp.value +p_attr", Util.escapeAssertion("r.attp.value +p.attr"));
      assertEquals("r_attp.value *p_attr", Util.escapeAssertion("r.attp.value *p.attr"));
      assertEquals("r_attp.value /p_attr", Util.escapeAssertion("r.attp.value /p.attr"));
      assertEquals("!r_attp.value /p_attr", Util.escapeAssertion("!r.attp.value /p.attr"));
      assertEquals("g(r_sub, p_sub) == p_attr", Util.escapeAssertion("g(r.sub, p.sub) == p.attr"));
      assertEquals("g(r_sub,p_sub) == p_attr", Util.escapeAssertion("g(r.sub,p.sub) == p.attr"));
      assertEquals("(r_attp.value || p_attr)p_u", Util.escapeAssertion("(r.attp.value || p.attr)p.u"));
  }

    @Test
    public void testConvertInSyntax(){
        assertEquals("include(r_obj, r_sub)", Util.convertInSyntax("r_sub in r_obj"));
        assertEquals("include(r_obj, r_sub.name)", Util.convertInSyntax("r_sub.name in r_obj"));
        assertEquals("include(r_obj.name, r_sub.name)", Util.convertInSyntax("r_sub.name in r_obj.name"));
        assertEquals("include(r_obj, r_sub) && r.obj == p.obj", Util.convertInSyntax("r_sub in r_obj && r.obj == p.obj"));
    }

  @Test
  public void testRemoveComments(){
    assertEquals("r.act == p.act", Util.removeComments("r.act == p.act # comments"));
    assertEquals("r.act == p.act", Util.removeComments("r.act == p.act#comments"));
    assertEquals("r.act == p.act", Util.removeComments("r.act == p.act###"));
    assertEquals("", Util.removeComments("### comments"));
    assertEquals("r.act == p.act", Util.removeComments("r.act == p.act"));
  }

  @Test
  public void testSplitCommaDelimited(){
    assertNull(Util.splitCommaDelimited(null));
    assertArrayEquals(new String[]{"a", "b", "c"}, Util.splitCommaDelimited("a,b,c"));
    assertArrayEquals(new String[]{"a", "b", "c"}, Util.splitCommaDelimited("a, b, c"));
    assertArrayEquals(new String[]{"a", "b", "c"}, Util.splitCommaDelimited("a ,b ,c"));
    assertArrayEquals(new String[]{"a", "b", "c"}, Util.splitCommaDelimited("  a,     b   ,c     "));
    assertArrayEquals(new String[]{"a,b,c", "d,e", "f"}, Util.splitCommaDelimited("\"a,b,c\", \"d,e\", f"));
    assertArrayEquals(new String[]{"a", "b", "c"}, Util.splitCommaDelimited("\"a\", \"b\", \"c\""));
    assertArrayEquals(new String[]{"\"a", "\"b\"", "c\""}, Util.splitCommaDelimited("\"\"\"a\",\"\"\"b\"\"\",\"c\"\"\""));
    assertArrayEquals(new String[]{"\"a", "\"b\"", "c\""}, Util.splitCommaDelimited("\"\"\"a\",\"\"\"b\"\"\",\"c\"\"\""));
    assertArrayEquals(new String[]{"a b", "c", "d"}, Util.splitCommaDelimited("\"a b\", c, d"));
  }

  @Test
  public void testReplaceEval() {
      Util.logPrint(Util.replaceEval("eval(test)", "testEval"));
  }

  @Test
  public void testLruCache() {
      SyncedLRUCache<String, Integer> cache = new SyncedLRUCache<>(3);
      TestUtil.testCachePut(cache, "one", 1);
      TestUtil.testCachePut(cache, "two", 2);
      TestUtil.testCacheGet(cache, "one", 1, true);
      TestUtil.testCachePut(cache, "three", 3);
      TestUtil.testCachePut(cache, "four", 4);
      TestUtil.testCacheGet(cache, "two", 2, false);
      TestUtil.testCacheGet(cache, "one", 1, true);
      TestUtil.testCacheGet(cache, "three", 3, true);
      TestUtil.testCacheGet(cache, "four", 4, true);
  }
}
