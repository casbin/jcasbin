package org.casbin.jcasbin.main;

import com.googlecode.aviator.AviatorEvaluator;
import com.googlecode.aviator.AviatorEvaluatorInstance;

public class AviatorEvaluatorInstanceSharer {

    public static void updateInstance(){
        StaticHolder.INSTANCE=AviatorEvaluator.newInstance();
    }

    public static AviatorEvaluatorInstance getInstance(){
        return StaticHolder.INSTANCE;
    }

    private static class StaticHolder {
        private static AviatorEvaluatorInstance INSTANCE = AviatorEvaluator.newInstance();
    }
}
