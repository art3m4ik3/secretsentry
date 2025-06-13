import { expect, test, describe } from "bun:test";
import { filterRulesBySeverity } from "../src/rules/secretRules.js";
import { mergeConfig } from "../src/config.js";

describe("Rules for discovering secrets", () => {
  test("High severity rules should be defined", () => {
    const highRules = filterRulesBySeverity("high");
    expect(highRules.length).toBeGreaterThan(0);
    expect(highRules.every((rule) => rule.severity === "high")).toBe(true);
  });

  test("Severity filter should work correctly", () => {
    const highRules = filterRulesBySeverity("high");
    const mediumRules = filterRulesBySeverity("medium");
    const lowRules = filterRulesBySeverity("low");

    expect(lowRules.length).toBeGreaterThanOrEqual(mediumRules.length);
    expect(mediumRules.length).toBeGreaterThanOrEqual(highRules.length);
  });
});

describe("Configuration", () => {
  test("Merging configurations should work correctly", () => {
    const userConfig = {
      ignorePaths: ["custom-path"],
      maxCommits: 10,
    };

    const mergedConfig = mergeConfig(userConfig);
    expect(mergedConfig.ignorePaths).toContain("custom-path");
    expect(
      mergedConfig.ignorePaths.some((path) => path.includes("node_modules")),
    ).toBe(true);
    expect(mergedConfig.maxCommits).toBe(10);
    expect(mergedConfig.severityLevel).toBe("medium");
  });
});
