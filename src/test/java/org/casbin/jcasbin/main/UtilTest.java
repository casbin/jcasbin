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
