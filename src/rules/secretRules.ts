export interface SecretRule {
  name: string;
  description: string;
  regex: RegExp;
  severity: "low" | "medium" | "high";
}

export const secretRules: SecretRule[] = [
  {
    name: "AWS Access Key",
    description: "AWS Access Key ID",
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: "high",
  },
  {
    name: "AWS Secret Key",
    description: "AWS Secret Access Key",
    regex: /[0-9a-zA-Z/+]{40}/g,
    severity: "high",
  },
  {
    name: "GitHub Token",
    description: "GitHub Personal Access Token",
    regex: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}/g,
    severity: "high",
  },
  {
    name: "Generic API Key",
    description: "Generic API key patterns",
    regex:
      /[a-zA-Z0-9_-]*(api|key|token|secret|password|pwd|credentials)[a-zA-Z0-9_-]*[=:]["']?[a-zA-Z0-9_\-\.]{16,}/gi,
    severity: "medium",
  },
  {
    name: "Private Key",
    description: "Private key in PEM format",
    regex:
      /-----BEGIN PRIVATE KEY-----[a-zA-Z0-9/+\s]*-----END PRIVATE KEY-----/g,
    severity: "high",
  },
  {
    name: "RSA Private Key",
    description: "RSA private key in PEM format",
    regex:
      /-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9/+\s]*-----END RSA PRIVATE KEY-----/g,
    severity: "high",
  },
  {
    name: "SSH Private Key",
    description: "SSH private key",
    regex:
      /-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9/+\s]*-----END OPENSSH PRIVATE KEY-----/g,
    severity: "high",
  },
  {
    name: "Password in URL",
    description: "Password in URL",
    regex: /:\/\/[^:\/\s]+:[^@\/\s]+@[^\/\s]+/gi,
    severity: "high",
  },
  {
    name: "JWT Token",
    description: "JWT Token",
    regex: /eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    severity: "medium",
  },
  {
    name: "Google API Key",
    description: "Google API Key",
    regex: /AIza[0-9A-Za-z-_]{35}/g,
    severity: "high",
  },
  {
    name: "Firebase API Key",
    description: "Firebase API Key",
    regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,
    severity: "high",
  },
  {
    name: "Stripe API Key",
    description: "Stripe API Key",
    regex: /sk_live_[0-9a-zA-Z]{24}/g,
    severity: "high",
  },
  {
    name: "Stripe Publishable Key",
    description: "Stripe Publishable Key",
    regex: /pk_live_[0-9a-zA-Z]{24}/g,
    severity: "medium",
  },
  {
    name: "Square Access Token",
    description: "Square Access Token",
    regex: /sq0atp-[0-9A-Za-z-_]{22}/g,
    severity: "high",
  },
  {
    name: "Square OAuth Secret",
    description: "Square OAuth Secret",
    regex: /sq0csp-[0-9A-Za-z-_]{43}/g,
    severity: "high",
  },
  {
    name: "PayPal Braintree Access Token",
    description: "PayPal Braintree Access Token",
    regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g,
    severity: "high",
  },
  {
    name: "Mailgun API Key",
    description: "Mailgun API Key",
    regex: /key-[0-9a-zA-Z]{32}/g,
    severity: "high",
  },
  {
    name: "Mailchimp API Key",
    description: "Mailchimp API Key",
    regex: /[0-9a-f]{32}-us[0-9]{1,2}/g,
    severity: "high",
  },
  {
    name: "Slack Webhook",
    description: "Slack Webhook URL",
    regex:
      /https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8,10}\/B[a-zA-Z0-9_]{8,10}\/[a-zA-Z0-9_]{24}/g,
    severity: "high",
  },
  {
    name: "Slack API Token",
    description: "Slack API Token",
    regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
    severity: "high",
  },
  {
    name: "Twilio API Key",
    description: "Twilio API Key",
    regex: /SK[0-9a-fA-F]{32}/g,
    severity: "high",
  },
  {
    name: "NPM Access Token",
    description: "NPM Access Token",
    regex: /npm_[A-Za-z0-9]{36}/g,
    severity: "high",
  },
  {
    name: "Heroku API Key",
    description: "Heroku API Key",
    regex:
      /[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g,
    severity: "high",
  },
  {
    name: "OpenAI API Key",
    description: "OpenAI API Key",
    regex: /sk-[a-zA-Z0-9]{48}/g,
    severity: "high",
  },
  {
    name: "Password Assignment",
    description: "Прямое присваивание пароля",
    regex:
      /(password|passwd|pwd)(\s*=\s*["'])(?!.*\{\{)(?!.*\$\{)(?!.*<)[^"']{4,}["']/gi,
    severity: "medium",
  },
  {
    name: "Environment Variable",
    description: "Прямые присваивания переменных окружения с секретами",
    regex: /(SECRET|PASSWORD|PASSWD|PWD|TOKEN|KEY|APIKEY|API_KEY)=\S+/gi,
    severity: "low",
  },
  {
    name: "Algolia API Key",
    description: "Algolia API Key",
    regex: /[a-zA-Z0-9]{32}/g,
    severity: "high",
  },
  {
    name: "Facebook Access Token",
    description: "Facebook Access Token",
    regex: /EAACEdEose0cBA[0-9A-Za-z]+/g,
    severity: "high",
  },
  {
    name: "Facebook OAuth",
    description: "Facebook OAuth",
    regex:
      /[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]/g,
    severity: "high",
  },
  {
    name: "Twitter OAuth",
    description: "Twitter OAuth",
    regex:
      /[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]/g,
    severity: "high",
  },
  {
    name: "Twitter Access Token",
    description: "Twitter Access Token",
    regex: /[1-9][0-9]+-[0-9a-zA-Z]{40}/g,
    severity: "high",
  },
  {
    name: "LinkedIn OAuth",
    description: "LinkedIn OAuth",
    regex:
      /[l|L][i|I][n|N][k|K][e|E][d|D][i|I][n|N].*['|\"][0-9a-zA-Z]{12}['|\"]/g,
    severity: "high",
  },
  {
    name: "LinkedIn Secret Key",
    description: "LinkedIn Secret Key",
    regex:
      /[l|L][i|I][n|N][k|K][e|E][d|D][i|I][n|N].*['|\"][0-9a-zA-Z]{16}['|\"]/g,
    severity: "high",
  },
  {
    name: "Picatic API Key",
    description: "Picatic API Key",
    regex: /sk_live_[0-9a-z]{32}/g,
    severity: "high",
  },
  {
    name: "SendGrid API Key",
    description: "SendGrid API Key",
    regex: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g,
    severity: "high",
  },
  {
    name: "Shopify Shared Secret",
    description: "Shopify Shared Secret",
    regex: /shpss_[a-fA-F0-9]{32}/g,
    severity: "high",
  },
  {
    name: "Shopify Access Token",
    description: "Shopify Access Token",
    regex: /shpat_[a-fA-F0-9]{32}/g,
    severity: "high",
  },
  {
    name: "Shopify Custom App Access Token",
    description: "Shopify Custom App Access Token",
    regex: /shpca_[a-fA-F0-9]{32}/g,
    severity: "high",
  },
  {
    name: "Shopify Private App Access Token",
    description: "Shopify Private App Access Token",
    regex: /shppa_[a-fA-F0-9]{32}/g,
    severity: "high",
  },
  {
    name: "Amazon MWS Auth Token",
    description: "Amazon MWS Auth Token",
    regex:
      /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    severity: "high",
  },
  {
    name: "Twilio Account SID",
    description: "Twilio Account SID",
    regex: /AC[a-zA-Z0-9_\-]{32}/g,
    severity: "high",
  },
  {
    name: "Twilio Auth Token",
    description: "Twilio Auth Token",
    regex: /[a-zA-Z0-9_\-]{32}/g,
    severity: "high",
  },
  {
    name: "Azure SQL Connection String",
    description: "Azure SQL Connection String",
    regex:
      /Server=tcp:[\w\d\-\.]+\.database\.windows\.net,1433;Initial Catalog=[\w\d\-]+;Persist Security Info=False;User ID=[\w\d\-]+;Password=[\w\d\-]+;/g,
    severity: "high",
  },
  {
    name: "Azure Storage Account Key",
    description: "Azure Storage Account Key",
    regex:
      /DefaultEndpointsProtocol=https;AccountName=[\w\d\-]+;AccountKey=[\w\d\+\/=]+;EndpointSuffix=core\.windows\.net/g,
    severity: "high",
  },
  {
    name: "Azure Connection String",
    description: "Azure Connection String",
    regex:
      /DefaultEndpointsProtocol=http[s]?;AccountName=[\w\d\-]+;AccountKey=[\w\d\+\/=]+/g,
    severity: "high",
  },
  {
    name: "Firebase Database URL",
    description: "Firebase Database URL",
    regex: /https:\/\/[\w\d\-]+\.firebaseio\.com/g,
    severity: "medium",
  },
  {
    name: "Google Cloud Platform API Key",
    description: "Google Cloud Platform API Key",
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: "high",
  },
  {
    name: "Google OAuth Client ID",
    description: "Google OAuth Client ID",
    regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    severity: "medium",
  },
  {
    name: "Google OAuth Access Token",
    description: "Google OAuth Access Token",
    regex: /ya29\.[0-9A-Za-z\-_]+/g,
    severity: "high",
  },
  {
    name: "EC Private Key",
    description: "EC Private Key",
    regex:
      /-----BEGIN EC PRIVATE KEY-----[a-zA-Z0-9/+\s]*-----END EC PRIVATE KEY-----/g,
    severity: "high",
  },
  {
    name: "DSA Private Key",
    description: "DSA Private Key",
    regex:
      /-----BEGIN DSA PRIVATE KEY-----[a-zA-Z0-9/+\s]*-----END DSA PRIVATE KEY-----/g,
    severity: "high",
  },
  {
    name: "PKCS8 Private Key",
    description: "PKCS8 Private Key",
    regex:
      /-----BEGIN PRIVATE KEY-----[a-zA-Z0-9/+\s]*-----END PRIVATE KEY-----/g,
    severity: "high",
  },
  {
    name: "MongoDB Connection String",
    description: "MongoDB Connection String",
    regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@.*/g,
    severity: "high",
  },
  {
    name: "Telegram Bot API Token",
    description: "Telegram Bot API Token",
    regex: /[0-9]{9}:[a-zA-Z0-9_-]{35}/g,
    severity: "high",
  },
  {
    name: "Bitcoin Private Key",
    description: "Bitcoin Private Key (WIF)",
    regex: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g,
    severity: "high",
  },
  {
    name: "Ethereum Private Key",
    description: "Ethereum Private Key",
    regex: /0x[a-fA-F0-9]{64}/g,
    severity: "high",
  },
  {
    name: "Generic Secret",
    description: "Generic Secret with common keywords",
    regex:
      /(secret|token|key|api|password|credential)[\s\'\"\=\:]+[a-zA-Z0-9!@#$%^&*()-=_+{}|\[\]\\:";'<>?,./]{8,}/gi,
    severity: "medium",
  },
  {
    name: "NPM Registry Auth Token",
    description: "NPM Registry Auth Token",
    regex: /\/\/registry\.npmjs\.org\/:_authToken=[0-9a-zA-Z\-]+/g,
    severity: "high",
  },
  {
    name: "Cloudinary Basic Auth",
    description: "Cloudinary Basic Auth",
    regex: /cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+/g,
    severity: "high",
  },
  {
    name: "Square OAuth Secret",
    description: "Square OAuth Secret",
    regex: /sq0csp-[0-9A-Za-z\-_]{43}/g,
    severity: "high",
  },
  {
    name: "Dynatrace API Token",
    description: "Dynatrace API Token",
    regex: /dt0[a-zA-Z]{1}[0-9]{2}:[A-Z0-9]{24}/g,
    severity: "high",
  },
  {
    name: "Basic Auth Credentials",
    description: "Basic Auth Credentials",
    regex: /basic [a-zA-Z0-9=:_\+\/-]{5,100}/gi,
    severity: "high",
  },
  {
    name: "GitHub App Key",
    description: "GitHub App Key",
    regex:
      /(-----BEGIN RSA PRIVATE KEY-----)[a-zA-Z0-9\s\n\+\/=]*?(-----END RSA PRIVATE KEY-----)/g,
    severity: "high",
  },
  {
    name: "Hubspot API Key",
    description: "Hubspot API Key",
    regex: /[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12}/g,
    severity: "high",
  },
  {
    name: "Reddit Client Secret",
    description: "Reddit Client Secret",
    regex: /reddit(.{0,20})?[\'\"][0-9a-zA-Z]{14}[\'\"]?/gi,
    severity: "high",
  },
  {
    name: "Mapbox API Key",
    description: "Mapbox API Key",
    regex: /(pk|sk)\.eyJ[0-9a-zA-Z\-_]{50,}/g,
    severity: "high",
  },
  {
    name: "Discord Bot Token",
    description: "Discord Bot Token",
    regex: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g,
    severity: "high",
  },
  {
    name: "Airtable API Key",
    description: "Airtable API Key",
    regex: /air[a-z0-9_]{10,}.{0,50}key[pat]{3}_[a-z0-9]{14}/gi,
    severity: "high",
  },
  {
    name: "SSH Private Key Content",
    description: "SSH Private Key in PEM format",
    regex:
      /-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY( BLOCK)?-----[a-zA-Z0-9\s\n\+\/-=_]+?-----END (RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY( BLOCK)?-----/g,
    severity: "high",
  },
  {
    name: "Kubernetes Config",
    description: "Kubernetes Config Credentials",
    regex:
      /kubernetes(.{0,20})?(token|secret|key|bearer|certificate|auth|credential|config)[\s\=\:\"\']+[A-Za-z0-9=:_\+\/-]{10,}/gi,
    severity: "high",
  },
  {
    name: "Slack App Secret",
    description: "Slack App Secret",
    regex: /slack(.{0,20})?[\'\"][0-9a-zA-Z]{24}[\'\"]?/gi,
    severity: "high",
  },
  {
    name: "Stripe Restricted Key",
    description: "Stripe Restricted Key",
    regex: /rk_live_[0-9a-zA-Z]{24}/g,
    severity: "high",
  },
  {
    name: "JDBC Connection String",
    description: "JDBC Connection String with credentials",
    regex:
      /jdbc:mysql:\/\/[a-zA-Z0-9\-\.]+:?[0-9]*\/[a-zA-Z0-9_\-]+\?user=[a-zA-Z0-9_\-]+&password=[^&]*/g,
    severity: "high",
  },
  {
    name: "Slack Client Secret",
    description: "Slack Client Secret",
    regex: /slack(.{0,20})?[\'\"][0-9a-zA-Z]{32}[\'\"]?/gi,
    severity: "high",
  },
  {
    name: "CircleCI Access Token",
    description: "CircleCI Access Token",
    regex: /circle(.{0,20})?[\'\"][0-9a-f]{40}[\'\"]?/gi,
    severity: "high",
  },
  {
    name: "GitLab Access Token",
    description: "GitLab Access Token",
    regex: /gitlab(.{0,20})?[\'\"]glpat-[0-9a-zA-Z\-\_]{20}[\'\"]?/gi,
    severity: "high",
  },
  {
    name: "Microsoft Teams Webhook",
    description: "Microsoft Teams Incoming Webhook URL",
    regex:
      /https:\/\/[a-zA-Z0-9-]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\/IncomingWebhook\/[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+/g,
    severity: "high",
  },
  {
    name: "Django Secret Key",
    description: "Django Secret Key",
    regex: /SECRET_KEY\s*=\s*[\'\"]((?!\{\{).{10,})[\'\"]/gi,
    severity: "high",
  },
  {
    name: "Rails Secret Key Base",
    description: "Rails Secret Key Base",
    regex: /secret_key_base\s*:\s*[\'\"]((?!\{\{).{10,})[\'\"]/gi,
    severity: "high",
  },
  {
    name: "Laravel APP_KEY",
    description: "Laravel Application Key",
    regex: /APP_KEY\s*=\s*base64:[a-zA-Z0-9+\/=]{40,}/g,
    severity: "high",
  },
  {
    name: "Stripe Test Key",
    description: "Stripe Test API Key",
    regex: /sk_test_[0-9a-zA-Z]{24}/g,
    severity: "medium",
  },
  {
    name: "Stripe Test Publishable Key",
    description: "Stripe Test Publishable Key",
    regex: /pk_test_[0-9a-zA-Z]{24}/g,
    severity: "low",
  },
  {
    name: "NuGet API Key",
    description: "NuGet API Key",
    regex: /oy2[a-z0-9]{43}/gi,
    severity: "high",
  },
  {
    name: "Microsoft Azure Storage Account Key",
    description: "Microsoft Azure Storage Account Key",
    regex: /AccountKey=[a-zA-Z0-9+\/=]{88}/g,
    severity: "high",
  },
  {
    name: "Jenkins Credentials",
    description: "Jenkins Credentials XML",
    regex: /<password>(.*?)<\/password>/g,
    severity: "high",
  },
  {
    name: "Hashicorp Terraform API Token",
    description: "Terraform Cloud/Enterprise API Token",
    regex: /[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{67}/g,
    severity: "high",
  },
  {
    name: "Dropbox API Key",
    description: "Dropbox API Key/Token",
    regex: /sl\.[a-zA-Z0-9_-]{136}/g,
    severity: "high",
  },
  {
    name: "PayPal Client ID",
    description: "PayPal Client ID",
    regex: /client_id=(?:"|')?([a-zA-Z0-9]{80,})(?:"|')?/g,
    severity: "medium",
  },
  {
    name: "PyPI Upload Token",
    description: "PyPI Upload Token",
    regex: /pypi-AgEIcH[a-zA-Z0-9_-]{50,}/g,
    severity: "high",
  },
  {
    name: "Docker Hub Password",
    description: "Docker Hub Password in Docker config",
    regex: /"auth":\s*"[a-zA-Z0-9+\/=]{20,}"/g,
    severity: "high",
  },
  {
    name: "GraphQL Introspection",
    description: "GraphQL Introspection Results",
    regex: /__schema\s*:\s*\{\s*types\s*:/g,
    severity: "medium",
  },
  {
    name: "Elasticsearch Connection String",
    description: "Elasticsearch Connection String with credentials",
    regex: /https?:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+:\d+/g,
    severity: "high",
  },
  {
    name: "Okta API Token",
    description: "Okta API Token",
    regex: /00[a-zA-Z0-9_-]{40}/g,
    severity: "high",
  },
  {
    name: "Atlassian API Token",
    description: "Atlassian API Token",
    regex: /ATATx[a-zA-Z0-9_-]{27}/g,
    severity: "high",
  },
];

export function addCustomRule(rule: SecretRule): void {
  secretRules.push(rule);
}

export function filterRulesBySeverity(
  minSeverity: "low" | "medium" | "high",
): SecretRule[] {
  const severityLevels = {
    low: 0,
    medium: 1,
    high: 2,
  };

  const minLevel = severityLevels[minSeverity];

  return secretRules.filter((rule) => {
    const ruleLevel = severityLevels[rule.severity];
    return ruleLevel >= minLevel;
  });
}
