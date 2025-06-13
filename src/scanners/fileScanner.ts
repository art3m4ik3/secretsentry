import fs from "fs/promises";
import { glob } from "glob";
import { SecretRule } from "../rules/secretRules.js";
import { SecretSentryConfig } from "../config.js";

export interface SecretMatch {
  rule: SecretRule;
  filePath: string;
  lineNumber: number;
  line: string;
  match: string;
}

export async function scanFile(
  filePath: string,
  rules: SecretRule[],
): Promise<SecretMatch[]> {
  try {
    const content = await fs.readFile(filePath, "utf-8");
    const lines = content.split("\n");
    const matches: SecretMatch[] = [];

    const foundRanges = new Map<number, Set<string>>();

    const sortedRules = [...rules].sort((a, b) => {
      const severityLevels = { high: 2, medium: 1, low: 0 };
      return severityLevels[b.severity] - severityLevels[a.severity];
    });

    lines.forEach((line, lineIndex) => {
      if (!foundRanges.has(lineIndex)) {
        foundRanges.set(lineIndex, new Set<string>());
      }

      const lineRanges = foundRanges.get(lineIndex)!;

      for (const rule of sortedRules) {
        const regex = new RegExp(rule.regex);
        let match;

        regex.lastIndex = 0;

        while ((match = regex.exec(line)) !== null) {
          const matchStart = match.index;
          const matchEnd = match.index + match[0].length;
          const rangeStr = `${matchStart}-${matchEnd}`;

          let overlaps = false;

          for (const existingRange of lineRanges) {
            const [existingStart, existingEnd] = existingRange
              .split("-")
              .map(Number);

            if (
              (matchStart >= existingStart && matchStart < existingEnd) ||
              (matchEnd > existingStart && matchEnd <= existingEnd) ||
              (matchStart <= existingStart && matchEnd >= existingEnd)
            ) {
              overlaps = true;
              break;
            }
          }

          if (!overlaps) {
            lineRanges.add(rangeStr);

            matches.push({
              rule,
              filePath,
              lineNumber: lineIndex + 1,
              line: line.trim(),
              match: match[0],
            });
          }
        }
      }
    });

    return matches;
  } catch (error) {
    console.error(`Error when scanning a file ${filePath}:`, error);
    return [];
  }
}

export async function scanDirectory(
  dirPath: string,
  rules: SecretRule[],
  config: SecretSentryConfig,
): Promise<SecretMatch[]> {
  const ignorePatterns = config.ignorePaths;

  const files = await glob("**/*", {
    cwd: dirPath,
    ignore: ignorePatterns,
    nodir: true,
    absolute: true,
  });

  const allMatches: SecretMatch[] = [];

  for (const file of files) {
    const matches = await scanFile(file, rules);
    allMatches.push(...matches);
  }

  return allMatches;
}
