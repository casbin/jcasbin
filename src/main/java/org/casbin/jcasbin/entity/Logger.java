package org.casbin.jcasbin.entity;

import java.util.List;

public class Logger {
    List<String> explain;

    boolean result;

    public List<String> getExplain() {
        return explain;
    }

    public void setExplain(List<String> explain) {
        this.explain = explain;
    }

    public boolean isResult() {
        return result;
    }

    public void setResult(boolean result) {
        this.result = result;
    }

    public Logger(List<String> explain, boolean result) {
        this.explain = explain;
        this.result = result;
    }

    public Logger() {
    }

    @Override
    public String toString() {
        return "logger{" +
            "explain=" + explain +
            ", result=" + result +
            '}';
    }
}
