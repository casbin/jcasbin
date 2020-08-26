package org.casbin.jcasbin.util.function;

import com.googlecode.aviator.runtime.function.AbstractFunction;
import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorObject;
import org.casbin.jcasbin.util.BuiltInFunctions;

import java.util.Map;

/**
 * KeyMatch4Func is the wrapper for keyMatch4.
 */
public class KeyMatch4Func extends AbstractFunction {
    public AviatorObject call(Map<String, Object> env, AviatorObject arg1, AviatorObject arg2) {
        String key1 = FunctionUtils.getStringValue(arg1, env);
        String key2 = FunctionUtils.getStringValue(arg2, env);

        return AviatorBoolean.valueOf(BuiltInFunctions.keyMatch4(key1, key2));
    }

    @Override
    public String getName() {
        return "keyMatch4";
    }
}
