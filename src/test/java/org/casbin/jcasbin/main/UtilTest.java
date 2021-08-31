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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.casbin.jcasbin.util.Util;
import org.junit.Test;

public class UtilTest {

  @Test
  public void testEscapeAssertion(){
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
  }

  @Test
  public void testReplaceEval() {
      Util.logPrint(Util.replaceEval("eval(test)", "testEval"));
  }
}
