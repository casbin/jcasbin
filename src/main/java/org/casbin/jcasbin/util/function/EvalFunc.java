package org.casbin.jcasbin.util.function;

import com.googlecode.aviator.runtime.function.AbstractFunction;
import com.googlecode.aviator.runtime.function.FunctionUtils;
import com.googlecode.aviator.runtime.type.AviatorBoolean;
import com.googlecode.aviator.runtime.type.AviatorObject;
import org.casbin.jcasbin.util.BuiltInFunctions;

import java.util.Map;

/**
 * EvalFunc is the wrapper for eval.
 * @author tldyl
 * @since 2020-07-02
 */
public class EvalFunc extends AbstractFunction {
    @Override
    public AviatorObject call(Map<String, Object> env, AviatorObject arg1) {
        String ev = FunctionUtils.getStringValue(arg1, env);
        return AviatorBoolean.valueOf(BuiltInFunctions.eval(ev, env));
    }

    @Override
    public String getName() {
        return "eval";
    }
}
