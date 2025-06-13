export interface SecretSentryConfig {
  ignorePaths: string[];
  customRules: RegExp[];
  maxCommits: number;
  severityLevel: "low" | "medium" | "high";
}

export const defaultConfig: SecretSentryConfig = {
  ignorePaths: [
    "node_modules/**",
    "dist/**",
    "build/**",
    ".git/**",
    "**/*.lock",
    "package-lock.json",
    "yarn.lock",
    "bun.lockb",
    ".env.example",
    "**/*.test.ts",
    "**/*.test.js",
    "**/*.spec.ts",
    "**/*.spec.js",
    "**/*.min.js",
    "**/*.min.css",
    "**/vendor/**",
    "**/coverage/**",
    "**/target/**",
    "**/out/**",
    "**/.next/**",
    "**/.nuxt/**",
  ],
  customRules: [],
  maxCommits: 50,
  severityLevel: "medium",
};

export function mergeConfig(
  userConfig: Partial<SecretSentryConfig>,
): SecretSentryConfig {
  return {
    ...defaultConfig,
    ...userConfig,
    ignorePaths: [
      ...defaultConfig.ignorePaths,
      ...(userConfig.ignorePaths || []),
    ],
    customRules: [
      ...defaultConfig.customRules,
      ...(userConfig.customRules || []),
    ],
  };
}
