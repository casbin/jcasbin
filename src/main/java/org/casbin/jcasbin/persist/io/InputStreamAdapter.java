package org.casbin.jcasbin.persist.io;

import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Helper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

public class InputStreamAdapter implements Adapter {

    private final InputStream is;

    public InputStreamAdapter(InputStream is) {
        this.is = is;
    }

    @Override
    public void loadPolicy(Model model) {
        loadPolicyFromClassPath(model, Helper::loadPolicyLine);
    }

    @Override
    public void savePolicy(Model model) {
        throw new Error("not implemented");
    }

    @Override
    public void addPolicy(String sec, String ptype, List<String> rule) {
        throw new Error("not implemented");
    }

    @Override
    public void removePolicy(String sec, String ptype, List<String> rule) {
        throw new Error("not implemented");
    }

    @Override
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        throw new Error("not implemented");
    }

    private void loadPolicyFromClassPath(Model model, Helper.loadPolicyLineHandler<String, Model> handler) {
        BufferedReader br = new BufferedReader(new InputStreamReader(is));

        String line;
        try {
            while((line = br.readLine()) != null) {
                handler.accept(line, model);
            }

            is.close();
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw new Error("IO error occurred");
        }
    }

}
