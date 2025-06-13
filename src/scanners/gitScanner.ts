import { simpleGit } from "simple-git";
import { SecretRule } from "../rules/secretRules.js";
import { SecretMatch } from "./fileScanner.js";
import { SecretSentryConfig } from "../config.js";

export interface GitSecretMatch extends SecretMatch {
  commitHash: string;
  commitMessage: string;
  commitDate: string;
  author: string;
}

export async function scanGitHistory(
  repoPath: string,
  rules: SecretRule[],
  config: SecretSentryConfig,
): Promise<GitSecretMatch[]> {
  const git = simpleGit(repoPath);
  const isGitRepo = await git.checkIsRepo();

  if (!isGitRepo) {
    throw new Error(`${repoPath} is not a Git repository`);
  }

  const log = await git.log({ maxCount: config.maxCommits });
  const matches: GitSecretMatch[] = [];

  for (const commit of log.all) {
    const { hash, message, date, author_name } = commit;

    const diff = await git.show([hash]);

    for (const rule of rules) {
      const regex = new RegExp(rule.regex);
      let match;

      const lines = diff.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (line.startsWith("-")) {
          continue;
        }

        regex.lastIndex = 0;

        while ((match = regex.exec(line)) !== null) {
          matches.push({
            rule,
            filePath: "Commit",
            lineNumber: i + 1,
            line: line.trim(),
            match: match[0],
            commitHash: hash,
            commitMessage: message,
            commitDate: date,
            author: author_name,
          });
        }
      }
    }
  }

  return matches;
}
