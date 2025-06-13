const core = require("@actions/core");
const exec = require("@actions/exec");
const path = require("path");

async function run() {
  try {
    const scanPath = core.getInput("path");
    const gitHistory = core.getInput("git-history") === "true";
    const maxCommits = core.getInput("max-commits");
    const severity = core.getInput("severity");
    const verbose = core.getInput("verbose") === "true";

    let command = ["scan", "--path", scanPath];

    if (gitHistory) {
      command.push("--git-history");
    }

    command.push("--max-commits", maxCommits);
    command.push("--severity", severity);

    if (verbose) {
      command.push("--verbose");
    }

    const options = {
      cwd: process.cwd(),
      failOnStdErr: false,
    };

    const packageDir = path.join(__dirname, "..", "..");
    core.info(`Executing SecretSentry from ${packageDir}`);

    await exec.exec("npm", ["install", "--no-save", packageDir], options);

    await exec.exec("npx", ["secretsentry", ...command], options);
  } catch (error) {
    if (error.code === 1) {
      core.setFailed("Обнаружены секреты высокой важности в репозитории");
    } else {
      core.setFailed(`Ошибка: ${error.message}`);
    }
  }
}

run();
