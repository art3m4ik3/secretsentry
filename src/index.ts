#!/usr/bin/env node

import { Command } from "commander";
import path from "path";
import fs from "fs";
import { scanDirectory, SecretMatch } from "./scanners/fileScanner.js";
import { scanGitHistory, GitSecretMatch } from "./scanners/gitScanner.js";
import { filterRulesBySeverity } from "./rules/secretRules.js";
import { defaultConfig, mergeConfig, SecretSentryConfig } from "./config.js";
import { printSummary } from "./utils/formatter.js";

const program = new Command();

program
  .name("secretsentry")
  .description("A tool for finding leaked secrets in the code")
  .version("1.0.0");

program
  .command("scan")
  .description("Scan the project for secrets")
  .option("-p, --path <path>", "Path to the directory to scan", process.cwd())
  .option("-g, --git-history", "Scan Git history", false)
  .option("-c, --config <path>", "Path to the configuration file")
  .option("-v, --verbose", "Show detailed information", false)
  .option(
    "-s, --severity <level>",
    "Minimum severity level (low, medium, high)",
    "medium",
  )
  .option("--show-secrets", "Show found secrets (dangerous!)", false)
  .option("--max-commits <number>", "Maximum number of commits to scan", "50")
  .action(async (options) => {
    try {
      console.log("🔍 SecretSentry starting scan...");

      let config: SecretSentryConfig = defaultConfig;

      if (options.config) {
        try {
          const configPath = path.resolve(options.config);
          const userConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
          config = mergeConfig(userConfig);
        } catch (error) {
          console.error("Error loading configuration:", error);
        }
      }

      config.severityLevel = options.severity || config.severityLevel;
      config.maxCommits = parseInt(options.maxCommits) || config.maxCommits;

      const rules = filterRulesBySeverity(config.severityLevel);

      console.log(`📋 Using ${rules.length} detection rules`);

      const targetPath = path.resolve(options.path);
      console.log(`📂 Scanning directory: ${targetPath}`);

      let fileMatches: SecretMatch[] = [];
      let gitMatches: GitSecretMatch[] = [];

      fileMatches = await scanDirectory(targetPath, rules, config);
      console.log(`🔎 Found potential secrets in files: ${fileMatches.length}`);

      if (options.gitHistory) {
        console.log(
          `📜 Scanning Git history (last ${config.maxCommits} commits)...`,
        );

        try {
          gitMatches = await scanGitHistory(targetPath, rules, config);
          console.log(
            `🔎 Found potential secrets in Git history: ${gitMatches.length}`,
          );
        } catch (error) {
          console.error("Error scanning Git history:", error);
        }
      }

      printSummary(fileMatches, gitMatches, options.verbose);

      const uniqueSecrets = new Map<string, boolean>();

      [...fileMatches, ...gitMatches].forEach((match) => {
        const key = `${match.filePath}:${match.lineNumber}:${match.match}`;
        uniqueSecrets.set(key, true);
      });

      const highSeverityMatches = [...fileMatches, ...gitMatches].filter(
        (match) => match.rule.severity === "high",
      );

      const highSeverityUniqueSecrets = new Map<string, boolean>();

      highSeverityMatches.forEach((match) => {
        const key = `${match.filePath}:${match.lineNumber}:${match.match}`;
        highSeverityUniqueSecrets.set(key, true);
      });

      if (highSeverityUniqueSecrets.size > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error("An error occurred:", error);
      process.exit(1);
    }
  });

program.parse();
