package org.casbin.jcasbin.cli;

import org.apache.commons.cli.*;
import org.casbin.jcasbin.main.Enforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Client {
    private static final Logger log = LoggerFactory.getLogger(Client.class);

    public static void main(String[] args) {
        try {
            boolean res = clientEnforce(args);
            log.info("Result: {}", res);
        } catch (ParseException e) {
            log.error(e.getMessage());
        }
    }

    public static boolean clientEnforce(String[] args) throws ParseException {
        Options options = new Options();
        Option model = new Option("m", "model", true, "the path of the model file");
        options.addOption(model);
        Option config = new Option("p", "policy", true, "the path of the policy file");
        options.addOption(config);
        Option enforceCMD = new Option("e", "enforce", true, "enforce");
        options.addOption(enforceCMD);
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        String modelPath = cmd.getOptionValue("model");
        String policyFile = cmd.getOptionValue("policy");
        Enforcer e = new Enforcer(modelPath, policyFile);
        String enforce = cmd.getOptionValue("enforce");
        return e.enforce(enforce.split(","));
    }
}
