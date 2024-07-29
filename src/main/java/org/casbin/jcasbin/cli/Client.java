package org.casbin.jcasbin.cli;

import org.apache.commons.cli.*;
import org.casbin.jcasbin.main.Enforcer;

public class Client {

    public static void main(String[] args) {
        try {
            Object res = clientEnforce(args);
            System.out.println(res);
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    public static Object clientEnforce(String[] args) throws ParseException {
        Options options = new Options();
        Option model = new Option("m", "model", true, "the path of the model file");
        options.addOption(model);
        Option config = new Option("p", "policy", true, "the path of the policy file");
        options.addOption(config);
        Option enforceCMD = new Option("e", "enforce", true, "enforce");
        options.addOption(enforceCMD);
        Option enforceExCMD = new Option("ex", "enforceEx", true, "enforceEx");
        options.addOption(enforceExCMD);
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        String modelPath = cmd.getOptionValue("model");
        String policyFile = cmd.getOptionValue("policy");
        Enforcer e = new Enforcer(modelPath, policyFile);
        if (cmd.hasOption("enforce")) {
            String enforceArgs = cmd.getOptionValue("enforce");
            return e.enforce(enforceArgs.split(","));
        } else if (cmd.hasOption("enforceEx")) {
            String enforceExArgs = cmd.getOptionValue("enforceEx");
            return e.enforceEx(enforceExArgs.split(","));
        } else {
            return null;
        }
    }
}
