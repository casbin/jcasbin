package org.casbin.jcasbin.main;

import static org.junit.Assert.assertEquals;

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
}