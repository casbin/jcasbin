// Copyright 2017 The casbin Authors. All Rights Reserved.
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

import com.googlecode.aviator.AviatorEvaluator;
import com.googlecode.aviator.AviatorEvaluatorInstance;
import com.googlecode.aviator.Expression;
import com.googlecode.aviator.runtime.type.AviatorFunction;
import org.casbin.jcasbin.effect.DefaultEffector;
import org.casbin.jcasbin.effect.Effect;
import org.casbin.jcasbin.effect.Effector;
import org.casbin.jcasbin.effect.StreamEffector;
import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.exception.CasbinEffectorException;
import org.casbin.jcasbin.exception.CasbinMatcherException;
import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.*;
import org.casbin.jcasbin.rbac.DomainManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.EnforceContext;
import org.casbin.jcasbin.util.Util;

import java.util.*;
import java.util.function.BiPredicate;

/**
 * CoreEnforcer defines the core functionality of an enforcer.
 */
public class CoreEnforcer {
    String modelPath;
    Model model;
    FunctionMap fm;
    private Effector eft;

    Adapter adapter;
    Watcher watcher;
    Dispatcher dispatcher;
    Map<String, RoleManager> rmMap;

    private boolean enabled;
    boolean autoSave;
    boolean autoBuildRoleLinks;
    boolean autoNotifyWatcher = true;
    boolean autoNotifyDispatcher = true;

    private AviatorEvaluatorInstance aviatorEval;

    void initialize() {
        rmMap = new HashMap<>();
        eft = new DefaultEffector();
        watcher = null;

        enabled = true;
        autoSave = true;
        autoBuildRoleLinks = true;
        dispatcher = null;
        aviatorEval = AviatorEvaluator.newInstance();
        initRmMap();
        initBuiltInFunction();
    }

    /**
     * newModel creates a model.
     *
     * @return an empty model.
     */
    public static Model newModel() {
        Model m = new Model();

        return m;
    }

    /**
     * newModel creates a model.
     *
     * @param text the model text.
     * @return the model.
     */
    public static Model newModel(String text) {
        Model m = new Model();

        m.loadModelFromText(text);

        return m;
    }

    /**
     * newModel creates a model.
     *
     * @param modelPath the path of the model file.
     * @param unused    unused parameter, just for differentiating with
     *                  newModel(String text).
     * @return the model.
     */
    public static Model newModel(String modelPath, String unused) {
        Model m = new Model();

        if (!modelPath.equals("")) {
            m.loadModel(modelPath);
        }

        return m;
    }


    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated
     * and needs to be reloaded by calling LoadPolicy().
     */
    public void loadModel() {
        model = newModel();
        model.loadModel(this.modelPath);
        model.printModel();
        fm = FunctionMap.loadFunctionMap();
    }

    /**
     * getModel gets the current model.
     *
     * @return the model of the enforcer.
     */
    public Model getModel() {
        return model;
    }

    /**
     * setModel sets the current model.
     *
     * @param model the model.
     */
    public void setModel(Model model) {
        this.model = model;
        fm = FunctionMap.loadFunctionMap();
    }

    /**
     * getAdapter gets the current adapter.
     *
     * @return the adapter of the enforcer.
     */
    public Adapter getAdapter() {
        return adapter;
    }

    /**
     * setAdapter sets the current adapter.
     *
     * @param adapter the adapter.
     */
    public void setAdapter(Adapter adapter) {
        this.adapter = adapter;
    }

    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    public void setWatcher(Watcher watcher) {
        this.watcher = watcher;
        watcher.setUpdateCallback(this::loadPolicy);
    }

    /**
     * setDispatcher sets the current dispatcher.
     *
     * @param dispatcher jCasbin dispatcher
     */
    public void setDispatcher(Dispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    /**
     * getRmMap gets the current role manager map.
     *
     * @return the role manager map of the enforcer.
     */
    public Map<String, RoleManager> getRmMap() {
        return rmMap;
    }

    /**
     * getRoleManager gets the current role manager.
     *
     * @return the role manager.
     */
    public RoleManager getRoleManager() {
        return rmMap.get("g");
    }

    /**
     * getNamedRoleManager gets the role manager for the named policy.
     *
     * @param ptype the policy type.
     * @return the role manager.
     */
    public RoleManager getNamedRoleManager(String ptype) {
        return rmMap.get(ptype);
    }

    /**
     * setRoleManager sets the current role manager for g.
     *
     * @param rm the role manager.
     */
    public void setRoleManager(RoleManager rm) {
        setRoleManager("g", rm);
    }

    /**
     * setNamedRoleManager sets the role manager for the named policy.
     *
     * @param ptype the policy type.
     * @param rm    the role manager.
     */
    public void setNamedRoleManager(String ptype, RoleManager rm) {
        setRoleManager(ptype, rm);
    }

    /**
     * setEffector sets the current effector.
     *
     * @param eft the effector.
     */
    public void setEffector(Effector eft) {
        this.eft = eft;
    }

    /**
     * clearPolicy clears all policy.
     */
    public void clearPolicy() {
        model.clearPolicy();
    }

    /**
     * loadPolicy reloads the policy from file/database.
     */
    public void loadPolicy() {
        model.clearPolicy();
        adapter.loadPolicy(model);
        model.sortPoliciesByPriority();
        model.sortPoliciesBySubjectHieraichy();

        clearRmMap();
        if (Util.enableLog) {
            model.printPolicy();
        }
        if (autoBuildRoleLinks) {
            buildRoleLinks();
        }
    }

    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    public void loadFilteredPolicy(Object filter) {
        model.clearPolicy();
        FilteredAdapter filteredAdapter;
        if (adapter instanceof FilteredAdapter) {
            filteredAdapter = (FilteredAdapter) adapter;
        } else {
            throw new CasbinAdapterException("Filtered policies are not supported by this adapter.");
        }
        try {
            filteredAdapter.loadFilteredPolicy(model, filter);
        } catch (Exception e) {
            e.printStackTrace();
        }
        model.sortPoliciesByPriority();
        model.sortPoliciesBySubjectHieraichy();

        initRmMap();
        if (Util.enableLog) {
            model.printPolicy();
        }
        if (autoBuildRoleLinks) {
            buildRoleLinks();
        }
    }

    /**
     * isFiltered returns true if the loaded policy has been filtered.
     *
     * @return if the loaded policy has been filtered.
     */
    public boolean isFiltered() {
        if (adapter instanceof FilteredAdapter) {
            return ((FilteredAdapter) adapter).isFiltered();
        }
        return false;
    }

    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    public void savePolicy() {
        if (isFiltered()) {
            throw new IllegalArgumentException("cannot save a filtered policy");
        }

        adapter.savePolicy(model);
        if (watcher != null && autoNotifyWatcher) {
            if (watcher instanceof WatcherEx) {
                ((WatcherEx) watcher).updateForSavePolicy(model);
            } else {
                watcher.update();
            }
        }
    }

    /**
     * setRoleManager sets role manager for ptype.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rm    the role manager.
     */
    public void setRoleManager(String ptype, RoleManager rm) {
        rmMap.put(ptype, rm);
    }

    /**
     * initRmMap initializes rmMap.
     */
    private void initRmMap() {
        if (!model.model.containsKey("g")) {
            return;
        }

        for (String ptype : model.model.get("g").keySet()) {
            if (rmMap.containsKey(ptype)) {
                rmMap.get(ptype).clear();
            } else {
                addOrUpdateDomainManagerMatching(ptype);
            }
        }
    }

    /**
     * add or update the DomainManager object in rmMap and associate it with a specific domain matching function
     */
    private void addOrUpdateDomainManagerMatching(String ptype) {
        rmMap.put(ptype, new DomainManager(10));
        String matchFun = "keyMatch(r_dom, p_dom)";
        if (model.model.get("m").get("m").value.contains(matchFun)) {
            addNamedDomainMatchingFunc(ptype, "g", BuiltInFunctions::keyMatch);
        }
    }

    private void initBuiltInFunction() {
        for (Map.Entry<String, AviatorFunction> entry : fm.fm.entrySet()) {
            AviatorFunction function = entry.getValue();

            if (aviatorEval.containsFunction(function.getName())) {
                aviatorEval.removeFunction(function.getName());
            }
            aviatorEval.addFunction(function);
        }
    }

    /**
     * clearRmMap clears rmMap.
     */
    private void clearRmMap() {
        if (!model.model.containsKey("g")) {
            return;
        }

        for (String ptype : model.model.get("g").keySet()) {
            rmMap.get(ptype).clear();
        }
    }

    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is
     * disabled, all access will be allowed by the enforce() function.
     *
     * @param enable whether to enable the enforcer.
     */
    public void enableEnforce(boolean enable) {
        this.enabled = enable;
    }

    /**
     * enableLog changes whether to print Casbin log to the standard output.
     *
     * @param enable whether to enable Casbin's log.
     */
    public void enableLog(boolean enable) {
        Util.enableLog = enable;
    }

    /**
     * enableAutoSave controls whether to save a policy rule automatically to
     * the adapter when it is added or removed.
     *
     * @param autoSave whether to enable the AutoSave feature.
     */
    public void enableAutoSave(boolean autoSave) {
        this.autoSave = autoSave;
    }

    /**
     * enableAutoBuildRoleLinks controls whether to save a policy rule
     * automatically to the adapter when it is added or removed.
     *
     * @param autoBuildRoleLinks whether to automatically build the role links.
     */
    public void enableAutoBuildRoleLinks(boolean autoBuildRoleLinks) {
        this.autoBuildRoleLinks = autoBuildRoleLinks;
    }

    /**
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
     */
    public void buildRoleLinks() {
        for (RoleManager rm : rmMap.values()) {
            rm.clear();
        }
        model.buildRoleLinks(rmMap);
    }

    /**
     * enforce use a custom matcher to decide whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, explain, sub, obj, act), use model matcher by default when matcher is "" or null.
     *
     * @param matcher the custom matcher.
     * @param rvals   the request needs to be mediated, usually an array
     *                of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    private EnforceResult enforce(String matcher, Object... rvals) {
        if (!enabled) {
            return new EnforceResult(true, new ArrayList<>(Collections.singletonList("The enforcer is not enabled, allow all requests")));
        }

        boolean compileCached = true;
        if (fm.isModify) {
            compileCached = false;
            initBuiltInFunction();
            fm.isModify = false;
        }
        Map<String, AviatorFunction> gFunctions = new HashMap<>();
        if (model.model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.model.get("g").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();

                RoleManager rm = ast.rm;
                AviatorFunction aviatorFunction = BuiltInFunctions.GenerateGFunctionClass.generateGFunction(key, rm);
                gFunctions.put(key, aviatorFunction);
            }
        }
        for (AviatorFunction f : gFunctions.values()) {
            if (!aviatorEval.containsFunction(f.getName())) {
                aviatorEval.addFunction(f);
                compileCached = false;
            }
        }
        fm.setAviatorEval(aviatorEval);

        String rType = "r", pType = "p", eType = "e", mType = "m";
        if (rvals.length != 0) {
            if (rvals[0] instanceof EnforceContext) {
                EnforceContext enforceContext = (EnforceContext) rvals[0];
                rType = enforceContext.getrType();
                pType = enforceContext.getpType();
                eType = enforceContext.geteType();
                mType = enforceContext.getmType();
                rvals = Arrays.copyOfRange(rvals, 1, rvals.length);
            }
        }

        String expString;
        if (matcher == null || "".equals(matcher)) {
            expString = model.model.get("m").get(mType).value;
        } else {
            expString = Util.removeComments(Util.escapeAssertion(matcher));
        }

        expString = Util.convertInSyntax(expString);
        // Use md5 encryption as cacheKey to prevent expString from being too long
        Expression expression = aviatorEval.compile(Util.md5(expString), expString, compileCached);

        StreamEffector streamEffector = null;
        try {
            streamEffector = this.eft.newStreamEffector(model.model.get("e").get(eType).value);
        } catch (Exception e) {
            if (!(e instanceof UnsupportedOperationException)) {
                throw new CasbinEffectorException(e);
            }
        }

        Effect[] policyEffects;
        float[] matcherResults;
        final List<List<String>> policy = model.model.get("p").get(pType).policy;
        final String[] pTokens = model.model.get("p").get(pType).tokens;
        final int policyLen = policy.size();
        int explainIndex = -1;

        if (policyLen != 0) {
            policyEffects = new Effect[policyLen];
            matcherResults = new float[policyLen];

            for (int i = 0; i < policy.size(); i++) {
                List<String> pvals = policy.get(i);
                Map<String, Object> parameters = new HashMap<>(rvals.length + pTokens.length);
                getPTokens(parameters, pType, pvals, pTokens);
                getRTokens(parameters, rType, rvals);

                Object result = expression.execute(parameters);

                if (result instanceof Boolean) {
                    if (!((boolean) result)) {
                        policyEffects[i] = Effect.Indeterminate;
                    } else {
                        policyEffects[i] = Effect.Allow;
                    }
                    if (streamEffector == null) {
                        continue;
                    }
                } else if (result instanceof Double || result instanceof Long) {
                    if (((Number) result).floatValue() == 0) {
                        policyEffects[i] = Effect.Indeterminate;
                    } else {
                        matcherResults[i] = ((Number) result).floatValue();
                        policyEffects[i] = Effect.Allow;
                    }
                    if (streamEffector == null) {
                        continue;
                    }
                } else {
                    throw new CasbinMatcherException("matcher result should be Boolean, Double or Long");
                }
                if (policyEffects[i] == Effect.Allow && parameters.containsKey(pType + "_eft")) {
                    String eft = (String) parameters.get(pType + "_eft");
                    if ("allow".equals(eft)) {
                        policyEffects[i] = Effect.Allow;
                    } else if ("deny".equals(eft)) {
                        policyEffects[i] = Effect.Deny;
                    } else {
                        policyEffects[i] = Effect.Indeterminate;
                    }
                }

                if (streamEffector != null) {
                    boolean done = streamEffector.push(policyEffects[i], i, policyLen);
                    if (done) {
                        break;
                    }
                } else {
                    if ("priority(p_eft) || deny".equals(model.model.get("e").get(eType).value)) {
                        break;
                    }
                }
            }
            explainIndex = streamEffector.current().getExplainIndex();
        } else {
            policyEffects = new Effect[1];
            matcherResults = new float[1];

            String[] rTokens = model.model.get("r").get(rType).tokens;
            Map<String, Object> parameters = new HashMap<>(rTokens.length + pTokens.length);

            for (int j = 0; j < rTokens.length; j++) {
                parameters.put(rTokens[j], rvals[j]);
            }
            for (String token : pTokens) {
                parameters.put(token, "");
            }

            Object result = expression.execute(parameters);

            if (streamEffector != null) {
                if ((boolean) result) {
                    streamEffector.push(Effect.Allow, 0, 1);
                } else {
                    streamEffector.push(Effect.Indeterminate, 0, 1);
                }
            } else {
                if ((boolean) result) {
                    policyEffects[0] = Effect.Allow;
                } else {
                    policyEffects[0] = Effect.Indeterminate;
                }
            }
        }

        boolean result;

        if (streamEffector != null && streamEffector.current() != null) {
            result = streamEffector.current().hasEffect();
        } else {
            result = eft.mergeEffects(model.model.get("e").get(eType).value, policyEffects, matcherResults);
        }

        List<String> explain = new ArrayList<>();
        if (explainIndex != -1) {
            explain.addAll(policy.get(explainIndex));
        }

        Util.logEnforce(rvals, result, explain);
        return new EnforceResult(result, explain);
    }

    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    public boolean enforce(Object... rvals) {
        return enforce(null, rvals).isAllow();
    }

    /**
     * enforceWithMatcher use a custom matcher to decide whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "" or null.
     *
     * @param matcher the custom matcher.
     * @param rvals   the request needs to be mediated, usually an array
     *                of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    public boolean enforceWithMatcher(String matcher, Object... rvals) {
        return enforce(matcher, rvals).isAllow();
    }

    /**
     * enforceEx decides whether a "subject" can access "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     * the list explain, store matching rule.
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    public EnforceResult enforceEx(Object... rvals) {
        return enforce(null, rvals);
    }

    /**
     * enforceExWithMatcher use a custom matcher to decide whether a "subject" can access a "object" with the operation "action",
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "" or null.
     * the list explain, store matching rule.
     *
     * @param matcher the custom matcher.
     * @param rvals   the request needs to be mediated, usually an array
     *                of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    public EnforceResult enforceExWithMatcher(String matcher, Object... rvals) {
        return enforce(matcher, rvals);
    }

    /**
     * addNamedMatchingFunc add MatchingFunc by ptype RoleManager
     */
    public boolean addNamedMatchingFunc(String ptype, String name, BiPredicate<String, String> fn) {
        if (rmMap.containsKey(ptype)) {
            DomainManager rm = (DomainManager) rmMap.get(ptype);
            rm.addMatchingFunc(name, fn);
            clearRmMap();
            if (autoBuildRoleLinks) {
                buildRoleLinks();
            }
            return true;
        }
        return false;
    }

    /**
     * addNamedMatchingFunc add MatchingFunc by ptype RoleManager
     */
    public boolean addNamedDomainMatchingFunc(String ptype, String name, BiPredicate<String, String> fn) {
        if (rmMap.containsKey(ptype)) {
            DomainManager rm = (DomainManager) rmMap.get(ptype);
            rm.addDomainMatchingFunc(name, fn);
            clearRmMap();
            if (autoBuildRoleLinks) {
                buildRoleLinks();
            }
            return true;
        }
        return false;
    }

    private void getRTokens(Map<String, Object> parameters, String rType, Object... rvals) {
        String[] requestTokens = model.model.get("r").get(rType).tokens;
        if(requestTokens.length != rvals.length) {
            throw new CasbinMatcherException("invalid request size: expected " + requestTokens.length +
                ", got " + rvals.length + ", rvals: " + Arrays.toString(rvals));
        }
        for(int i = 0; i < requestTokens.length; i++) {
            parameters.put(requestTokens[i], rvals[i]);
        }
    }

    private void getPTokens(Map<String, Object> parameters, String pType, List<String> pvals, String[] pTokens) {
        if (pTokens.length != pvals.size()) {
            throw new CasbinMatcherException("invalid policy size: expected " + pTokens.length +
                ", got " + pvals.size() + ", pvals: " + pvals);
        }
        for (int i = 0; i < pTokens.length; i++) {
            parameters.put(pTokens[i], pvals.get(i));
        }
    }

    public boolean validateEnforce(Object... rvals) {
        return validateEnforceSection("r", rvals);
    }

    private boolean validateEnforceSection(String section, Object... rvals) {
        int expectedParamSize = getModel().model.entrySet().stream()
            .filter(stringMapEntry -> stringMapEntry.getKey().equals(section))
            .flatMap(stringMapEntry -> stringMapEntry.getValue().entrySet().stream())
            .filter(stringAssertionEntry -> stringAssertionEntry.getKey().equals(section))
            .findFirst().orElseThrow(
                () -> new CasbinMatcherException("Could not find " + section + " definition in model."))
            .getValue().tokens.length;

        if (rvals.length != expectedParamSize) {
            Util.logPrintfWarn("Incorrect number of attributes to check for policy (expected {} but got {})",
                expectedParamSize, rvals.length);
            return rvals.length >= expectedParamSize;
        }
        return true;
    }

    /**
     * Invalidate cache of compiled model matcher expression. This is done automatically most of the time, but you may
     * need to call it explicitly if you manipulate directly Model.
     */
    public void resetExpressionEvaluator() {
        fm.setAviatorEval(null);
    }

    public boolean isAutoNotifyWatcher() {
        return autoNotifyWatcher;
    }

    public void setAutoNotifyWatcher(boolean autoNotifyWatcher) {
        this.autoNotifyWatcher = autoNotifyWatcher;
    }

    public boolean isAutoNotifyDispatcher() {
        return autoNotifyDispatcher;
    }

    public void setAutoNotifyDispatcher(boolean autoNotifyDispatcher) {
        this.autoNotifyDispatcher = autoNotifyDispatcher;
    }

    protected boolean mustUseDispatcher() {
        return this.dispatcher != null && this.autoNotifyDispatcher;
    }
}
