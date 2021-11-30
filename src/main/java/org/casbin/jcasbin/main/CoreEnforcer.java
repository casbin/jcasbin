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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.casbin.jcasbin.effect.DefaultEffector;
import org.casbin.jcasbin.effect.Effect;
import org.casbin.jcasbin.effect.Effector;
import org.casbin.jcasbin.effect.StreamEffector;
import org.casbin.jcasbin.effect.StreamEffectorResult;
import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.exception.CasbinEffectorException;
import org.casbin.jcasbin.exception.CasbinMatcherException;
import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Dispatcher;
import org.casbin.jcasbin.persist.FilteredAdapter;
import org.casbin.jcasbin.persist.Watcher;
import org.casbin.jcasbin.persist.WatcherEx;
import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.EnforceContext;
import org.casbin.jcasbin.util.Util;

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

    void initialize() {
        rmMap = new HashMap<>();
        eft = new DefaultEffector();
        watcher = null;

        enabled = true;
        autoSave = true;
        autoBuildRoleLinks = true;
        dispatcher = null;
        initRmMap();
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
     * @param unused unused parameter, just for differentiating with
     *               newModel(String text).
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
     * setRoleManager sets the current role manager for g.
     *
     * @param rm the role manager.
     */
    public void setRoleManager(RoleManager rm) {
        setRoleManager("g", rm);
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

        clearRmMap();
        model.printPolicy();
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

        initRmMap();
        model.printPolicy();
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
                rmMap.put(ptype, new DefaultRoleManager(10));
            }
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
     * input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "" or null.
     *
     * @param matcher the custom matcher.
     * @param rvals   the request needs to be mediated, usually an array
     *                of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    private boolean enforce(String matcher, Object... rvals) {
        if (!enabled) {
            return true;
        }

        Map<String, AviatorFunction> functions = new HashMap<>();
        for (Map.Entry<String, AviatorFunction> entry : fm.fm.entrySet()) {
            String key = entry.getKey();
            AviatorFunction function = entry.getValue();

            functions.put(key, function);
        }
        if (model.model.containsKey("g")) {
            for (Map.Entry<String, Assertion> entry : model.model.get("g").entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();

                RoleManager rm = ast.rm;
                functions.put(key, BuiltInFunctions.generateGFunction(key, rm));
            }
        }
        AviatorEvaluatorInstance aviatorEval = AviatorEvaluator.newInstance();
        for (AviatorFunction f : functions.values()) {
            if (aviatorEval.containsFunction(f.getName())) {
                aviatorEval.removeFunction(f.getName());
            }
            aviatorEval.addFunction(f);
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
        Expression expression = aviatorEval.compile(expString, true);

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
        int policyLen;
        if ((policyLen = model.model.get("p").get(pType).policy.size()) != 0) {
            policyEffects = new Effect[policyLen];
            matcherResults = new float[policyLen];

            for (int i = 0; i < model.model.get("p").get(pType).policy.size(); i++) {
                List<String> pvals = model.model.get("p").get(pType).policy.get(i);

                // Util.logPrint("Policy Rule: " + pvals);
                // Select the rule based on request size
                Map<String, Object> parameters = new HashMap<>();
                getRTokens(parameters, rvals);
                for (int j = 0; j < model.model.get("p").get(pType).tokens.length; j++) {
                    String token = model.model.get("p").get(pType).tokens[j];
                    parameters.put(token, pvals.get(j));
                }

                Object result = expression.execute(parameters);
                // Util.logPrint("Result: " + result);

                if (result instanceof Boolean) {
                    if (!((boolean) result)) {
                        policyEffects[i] = Effect.Indeterminate;
                    } else {
                        policyEffects[i] = Effect.Allow;
                    }
                    if (streamEffector == null) {
                        continue;
                    }
                } else if (result instanceof Float) {
                    if ((float) result == 0) {
                        policyEffects[i] = Effect.Indeterminate;
                    } else {
                        matcherResults[i] = (float) result;
                        policyEffects[i] = Effect.Allow;
                    }
                    if (streamEffector == null) {
                        continue;
                    }
                } else {
                    throw new CasbinMatcherException("matcher result should be bool, int or float");
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
        } else {
            policyEffects = new Effect[1];
            matcherResults = new float[1];

            Map<String, Object> parameters = new HashMap<>();
            for (int j = 0; j < model.model.get("r").get(rType).tokens.length; j++) {
                String token = model.model.get("r").get(rType).tokens[j];
                parameters.put(token, rvals[j]);
            }
            for (int j = 0; j < model.model.get("p").get(pType).tokens.length; j++) {
                String token = model.model.get("p").get(pType).tokens[j];
                parameters.put(token, "");
            }

            Object result = expression.execute(parameters);
            // Util.logPrint("Result: " + result);

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

        StringBuilder reqStr = new StringBuilder("Request: ");
        for (int i = 0; i < rvals.length; i++) {
            String rval = rvals[i].toString();

            if (i != rvals.length - 1) {
                reqStr.append(String.format("%s, ", rval));
            } else {
                reqStr.append(String.format("%s", rval));
            }
        }
        reqStr.append(String.format(" ---> %s", result));
        Util.logPrint(reqStr.toString());

        return result;
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
        return enforce(null, rvals);
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
        return enforce(matcher, rvals);
    }

    private void getRTokens(Map<String, Object> parameters, Object... rvals) {
        for (String rKey : model.model.get("r").keySet()) {
            if (!(rvals.length == model.model.get("r").get(rKey).tokens.length)) {
                continue;
            }
            for (int j = 0; j < model.model.get("r").get(rKey).tokens.length; j++) {
                String token = model.model.get("r").get(rKey).tokens[j];
                parameters.put(token, rvals[j]);
            }

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
                () -> new CasbinMatcherException("Could not find " + section + " definition in model"))
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
}
