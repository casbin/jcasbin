package org.casbin.jcasbin.main;

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.util.Util;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * CachedEnforcer wraps Enforcer and provides decision cache
 *
 * @author canxer314
 */
public class CachedEnforcer extends Enforcer {
    private final static ReadWriteLock READ_WRITE_LOCK = new ReentrantReadWriteLock();
    private final static Map<String, Boolean> cacheMap = new HashMap();
    private boolean enableCathe = true;

    /**
     * ;
     * CachedEnforcer is the default constructor.
     */
    public CachedEnforcer() {
        super();
    }

    /**
     * CachedEnforcer initializes an enforcer with a model file and a policy file.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     */
    public CachedEnforcer(String modelPath, String policyFile) {
        super(modelPath, policyFile);
    }

    /**
     * CachedEnforcer initializes an enforcer with a database adapter.
     *
     * @param modelPath the path of the model file.
     * @param adapter   the adapter.
     */
    public CachedEnforcer(String modelPath, Adapter adapter) {
        super(modelPath, adapter);
    }

    /**
     * CachedEnforcer initializes an enforcer with a model and a database adapter.
     *
     * @param m       the model.
     * @param adapter the adapter.
     */
    public CachedEnforcer(Model m, Adapter adapter) {
        super(m, adapter);
    }

    /**
     * CachedEnforcer initializes an enforcer with a model.
     *
     * @param m the model.
     */
    public CachedEnforcer(Model m) {
        super(m);
    }

    /**
     * CachedEnforcer initializes an enforcer with a model file.
     *
     * @param modelPath the path of the model file.
     */
    public CachedEnforcer(String modelPath) {
        super(modelPath);
    }

    /**
     * CachedEnforcer initializes an enforcer with a model file, a policy file and an enable log flag.
     *
     * @param modelPath  the path of the model file.
     * @param policyFile the path of the policy file.
     * @param enableLog  whether to enable Casbin's log.
     */
    public CachedEnforcer(String modelPath, String policyFile, boolean enableLog) {
        super(modelPath, policyFile, enableLog);
    }

    public void enableCache(boolean enableCathe) {
        this.enableCathe = enableCathe;
    }

    private boolean isEnableCathe() {
        return this.enableCathe;
    }

    @Override
    public boolean enforce(Object... rvals) {
        if (!isEnableCathe()) {
            return super.enforce(rvals);
        }

        StringBuilder key = new StringBuilder();
        for (Object rval : rvals) {
            try {
                key.append(rval.toString());
                key.append("$$");
            } catch (Exception e) {
                return super.enforce(rvals);
            }
        }

        Boolean res = getCachedResult(key.toString());
        if (res != null) {
            return res;
        }

        res = super.enforce(rvals);
        setCachedResult(key.toString(), res);
        return res;
    }

    public boolean getCachedResult(String key) {
        try {
            READ_WRITE_LOCK.readLock().lock();
            return cacheMap.getOrDefault(key, null);
        } finally {
            READ_WRITE_LOCK.readLock().unlock();
        }
    }

    public void setCachedResult(String key, boolean bool) {
        try {
            READ_WRITE_LOCK.writeLock().lock();
            cacheMap.put(key, bool);
        } finally {
            READ_WRITE_LOCK.writeLock().unlock();
        }
    }

    public void invalidateCache() {
        cacheMap.clear();
    }

}
