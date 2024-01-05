package org.casbin.jcasbin.main;

import org.casbin.jcasbin.config.Config;

import org.junit.Test;
import static org.junit.Assert.*;

public class ConfigTest {

    @Test
    public void testGet() {
        Config config = Config.newConfig("examples/config/testini.ini");

        // default::key test
        assertTrue(config.getBool("debug"));
        assertEquals("act.wiki", config.getString("url"));

        // redis::key test
        String[] redisKeys = config.getStrings("redis::redis.key");
        assertArrayEquals(new String[]{"push1", "push2"}, redisKeys);
        assertEquals("127.0.0.1", config.getString("mysql::mysql.dev.host"));
        assertEquals("10.0.0.1", config.getString("mysql::mysql.master.host"));
        assertEquals("root", config.getString("mysql::mysql.master.user"));
        assertEquals("89dds)2$", config.getString("mysql::mysql.master.pass"));

        // math::key test
        assertEquals(64, config.getInt("math::math.i64"));
        assertEquals(64.1, config.getFloat("math::math.f64"), 0.0001);

        config.set("other::key1", "new test key");
        assertEquals("new test key", config.getString("other::key1"));

        config.set("other::key1", "test key");

        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi1::name"));
        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi2::name"));
        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi3::name"));
        assertEquals("", config.getString("multi4::name"));
        assertEquals("r.sub==p.sub && r.obj==p.obj", config.getString("multi5::name"));
    }
}
