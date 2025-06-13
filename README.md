# SecretSentry

SecretSentry is a tool for finding leaked secrets in code and commit history

## Features

- Search for secrets in project files
- Scan Git commit history
- 50+ built-in rules for detecting secrets in popular services
- Customizable detection rules
- Ignore nested folders and files
- Smart deduplication of secrets based on severity level
- Integration with GitHub Actions

## Supported Services

SecretSentry detects secrets for over 50 popular services, including:

- AWS (Access Keys, Secret Keys)
- GitHub (Personal Access Tokens)
- Google Cloud Platform (API Keys)
- Firebase
- Stripe, PayPal, Square and other payment systems
- Slack, Discord, Telegram
- OpenAI API Keys
- Azure, MongoDB, PostgreSQL
- OAuth tokens (Google, Facebook, Twitter)
- JWT tokens
- SSH and RSA private keys
- And many more

## Installation

```bash
# Using npm
npm install -g secretsentry

# Using yarn
yarn global add secretsentry

# Using pnpm
pnpm add -g secretsentry

# Using bun
bun add -g secretsentry
```

## Usage

```bash
# Scanning the current directory
secretsentry scan

# Scanning a specific dir
secretsentry scan --path /path/to/project

# Scanning Git history
secretsentry scan --git-history

# Show detailed information
secretsentry scan --verbose

# Set minimum severity level (low, medium, high)
secretsentry scan --severity low

# Limit the number of commits to scan
secretsentry scan --git-history --max-commits 100

# Use a custom configuration file
secretsentry scan --config /path/to/config.json
```

## Integration with GitHub Actions

Example workflow for scanning secrets in a GitHub repository:

```yaml
name: Secret Scanner

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: "0 0 * * 0"

jobs:
  scan:
    name: Scan for secrets
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Scan for secrets
        uses: art3m4ik3/secretsentry@v1
        with:
          path: "."
          git-history: "true"
          max-commits: "100"
          severity: "medium"
          verbose: "true"
```
