package org.casbin.jcasbin.persist;

import org.casbin.jcasbin.model.Model;

import java.util.Arrays;
import java.util.function.BiFunction;

public class Helper {
    public interface loadPolicyLineHandler<T, U> {
        void accept(T t, U u);
    }

    public static void loadPolicyLine(String line, Model model) {
        if (line.equals("")) {
            return;
        }

        if (line.charAt(0) == '#') {
            return;
        }

        String[] tokens = line.split(", ");

        String key = tokens[0];
        String sec = key.substring(0, 1);
        model.model.get(sec).get(key).policy.add(Arrays.asList(Arrays.copyOfRange(tokens, 1, tokens.length)));
    }
}
