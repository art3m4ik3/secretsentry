import chalk from "chalk";
import { SecretMatch } from "../scanners/fileScanner.js";
import { GitSecretMatch } from "../scanners/gitScanner.js";

export function formatSecretMatch(
  match: SecretMatch,
  showSecret: boolean = false,
): string {
  const severityColors = {
    low: chalk.blue,
    medium: chalk.yellow,
    high: chalk.red,
  };

  const severity = severityColors[match.rule.severity](
    match.rule.severity.toUpperCase(),
  );
  const rule = chalk.bold(match.rule.name);
  const file = chalk.cyan(match.filePath);
  const line = chalk.green(`Line ${match.lineNumber}`);

  let lineContent = match.line;

  if (!showSecret) {
    lineContent = lineContent.replace(match.match, chalk.bgRed("********"));
  }

  return `[${severity}] ${rule}\n  File: ${file}\n  ${line}\n  Code: ${lineContent}\n`;
}

export function formatGitSecretMatch(
  match: GitSecretMatch,
  showSecret: boolean = false,
): string {
  const severityColors = {
    low: chalk.blue,
    medium: chalk.yellow,
    high: chalk.red,
  };

  const severity = severityColors[match.rule.severity](
    match.rule.severity.toUpperCase(),
  );
  const rule = chalk.bold(match.rule.name);
  const commit = chalk.magenta(match.commitHash.substring(0, 7));
  const date = chalk.green(match.commitDate);
  const author = chalk.yellow(match.author);

  let lineContent = match.line;

  if (!showSecret) {
    lineContent = lineContent.replace(match.match, chalk.bgRed("********"));
  }

  return `[${severity}] ${rule}\n  Commit: ${commit} from ${date} (${author})\n  Message: ${match.commitMessage}\n  Code: ${lineContent}\n`;
}

export function printSummary(
  fileMatches: SecretMatch[],
  gitMatches: GitSecretMatch[] = [],
  verbose: boolean = false,
): void {
  const totalMatches = fileMatches.length + gitMatches.length;

  if (totalMatches === 0) {
    console.log(chalk.green.bold("✓ No secrets found!"));
    return;
  }

  const uniqueSecrets = new Map<string, SecretMatch | GitSecretMatch>();

  const allMatches = [...fileMatches, ...gitMatches];

  allMatches.sort((a, b) => {
    const severityLevels = { high: 2, medium: 1, low: 0 };
    return severityLevels[b.rule.severity] - severityLevels[a.rule.severity];
  });

  for (const match of allMatches) {
    const key = `${match.filePath}:${match.lineNumber}:${match.match}`;
    if (!uniqueSecrets.has(key)) {
      uniqueSecrets.set(key, match);
    }
  }

  const uniqueMatches = Array.from(uniqueSecrets.values());

  const highSeverityCount = uniqueMatches.filter(
    (match) => match.rule.severity === "high",
  ).length;

  const mediumSeverityCount = uniqueMatches.filter(
    (match) => match.rule.severity === "medium",
  ).length;

  const lowSeverityCount = uniqueMatches.filter(
    (match) => match.rule.severity === "low",
  ).length;

  const uniqueFileMatches = uniqueMatches.filter(
    (match) => !("commitHash" in match),
  ) as SecretMatch[];
  const uniqueGitMatches = uniqueMatches.filter(
    (match) => "commitHash" in match,
  ) as GitSecretMatch[];
  console.log(chalk.red.bold(`⚠ Secrets found: ${uniqueMatches.length}`));
  console.log(chalk.red(`  High severity: ${highSeverityCount}`));
  console.log(chalk.yellow(`  Medium severity: ${mediumSeverityCount}`));
  console.log(chalk.blue(`  Low severity: ${lowSeverityCount}`));
  console.log(chalk.gray(`  In files: ${uniqueFileMatches.length}`));
  console.log(chalk.gray(`  In Git history: ${uniqueGitMatches.length}`));

  if (verbose) {
    console.log("\nDetails of found secrets:");

    if (uniqueFileMatches.length > 0) {
      console.log(chalk.bold("\nSecrets in files:"));
      uniqueFileMatches.forEach((match) => {
        console.log(formatSecretMatch(match, false));
      });
    }

    if (uniqueGitMatches.length > 0) {
      console.log(chalk.bold("\nSecrets in Git history:"));
      uniqueGitMatches.forEach((match) => {
        console.log(formatGitSecretMatch(match, false));
      });
    }
  }
}
