# Built-in Rule Registry

All built-in rule IDs are stable. Users reference these in `disable_builtin` and allowlist config.

## Secret Rules (~40)

| ID | Category | Pattern hint | Severity |
|---|---|---|---|
| `aws-access-key` | AWS | `AKIA[0-9A-Z]{16}` | high |
| `aws-secret-key` | AWS | 40-char base64 after keyword | high |
| `aws-session-token` | AWS | Long base64 after keyword | high |
| `gcp-service-account` | GCP | `"type": "service_account"` | high |
| `gcp-api-key` | GCP | `AIza[0-9A-Za-z\-_]{35}` | medium |
| `azure-storage-key` | Azure | 88-char base64 after keyword | high |
| `azure-client-secret` | Azure | UUID-like after keyword | high |
| `openai-api-key` | AI | `sk-proj-[A-Za-z0-9]{20,}` | high |
| `openai-api-key-legacy` | AI | `sk-[A-Za-z0-9]{20,}` (no proj) | high |
| `anthropic-api-key` | AI | `sk-ant-[A-Za-z0-9]{20,}` | high |
| `github-pat` | VCS | `ghp_[A-Za-z0-9]{36}` | high |
| `github-oauth` | VCS | `gho_[A-Za-z0-9]{36}` | medium |
| `github-app-token` | VCS | `ghu_[A-Za-z0-9]{36}` | medium |
| `github-fine-grained` | VCS | `github_pat_[A-Za-z0-9]{22,}` | high |
| `gitlab-pat` | VCS | `glpat-[A-Za-z0-9\-]{20,}` | high |
| `gitlab-pipeline` | VCS | `glptt-[A-Za-z0-9\-]{20,}` | medium |
| `bitbucket-app-password` | VCS | `ATBB[A-Za-z0-9]{32,}` | high |
| `stripe-secret` | Payment | `sk_live_[A-Za-z0-9]{24,}` | high |
| `stripe-restricted` | Payment | `rk_live_[A-Za-z0-9]{24,}` | high |
| `stripe-publishable` | Payment | `pk_live_[A-Za-z0-9]{24,}` | low |
| `slack-bot-token` | Chat | `xoxb-[0-9]{10,}-[A-Za-z0-9]+` | high |
| `slack-user-token` | Chat | `xoxp-[0-9]{10,}-[A-Za-z0-9]+` | high |
| `slack-webhook` | Chat | `hooks.slack.com/services/T[A-Z0-9]+` | medium |
| `twilio-api-key` | Comms | `SK[a-f0-9]{32}` | high |
| `sendgrid-api-key` | Comms | `SG\.[A-Za-z0-9\-_]{22,}` | high |
| `mailgun-api-key` | Comms | `key-[a-f0-9]{32}` | medium |
| `jwt-token` | Auth | `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+` | medium |
| `private-key-pem` | Crypto | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | high |
| `private-key-generic` | Crypto | `-----BEGIN PRIVATE KEY-----` | high |
| `npm-token` | Registry | `npm_[A-Za-z0-9]{36}` | high |
| `pypi-token` | Registry | `pypi-[A-Za-z0-9]{50,}` | high |
| `nuget-api-key` | Registry | `oy2[a-z0-9]{43}` | medium |
| `heroku-api-key` | Cloud | UUID after heroku keyword | medium |
| `digitalocean-token` | Cloud | `dop_v1_[a-f0-9]{64}` | high |
| `databricks-token` | Data | `dapi[a-f0-9]{32}` | high |
| `postgres-uri` | DB | `postgres(ql)?://[^:]+:[^@]+@` | high |
| `mysql-uri` | DB | `mysql://[^:]+:[^@]+@` | high |
| `mongodb-uri` | DB | `mongodb(\+srv)?://[^:]+:[^@]+@` | high |
| `redis-uri` | DB | `redis://[^:]+:[^@]+@` | medium |
| `generic-api-key` | Generic | High-entropy string after `api[_-]?key` keyword | low |
| `generic-secret` | Generic | High-entropy string after `secret` keyword | low |
| `generic-password` | Generic | High-entropy string after `password` keyword | low |

## Sensitive File Rules (~30)

| ID | Pattern | Match type | Default action |
|---|---|---|---|
| `sf-dotenv` | `.env` | basename | block |
| `sf-dotenv-wildcard` | `.env.*` | glob | block |
| `sf-pem` | `*.pem` | glob | block |
| `sf-key` | `*.key` | glob | block |
| `sf-p12` | `*.p12` | glob | block |
| `sf-pfx` | `*.pfx` | glob | block |
| `sf-jks` | `*.jks` | glob | block |
| `sf-keychain` | `*.keychain-db` | glob | block |
| `sf-id-rsa` | `id_rsa` | basename | block |
| `sf-id-ed25519` | `id_ed25519` | basename | block |
| `sf-id-ecdsa` | `id_ecdsa` | basename | block |
| `sf-id-dsa` | `id_dsa` | basename | block |
| `sf-kubeconfig` | `kubeconfig` | basename | block |
| `sf-credentials` | `credentials` | basename | block |
| `sf-npmrc` | `.npmrc` | basename | block |
| `sf-pypirc` | `.pypirc` | basename | block |
| `sf-netrc` | `.netrc` | basename | block |
| `sf-pgpass` | `.pgpass` | basename | block |
| `sf-mycnf` | `.my.cnf` | basename | block |
| `sf-tfvars` | `terraform.tfvars` | basename | block |
| `sf-tfstate` | `*.tfstate` | glob | block |
| `sf-secrets-yaml` | `secrets.yaml` | basename | block |
| `sf-secrets-yml` | `secrets.yml` | basename | block |
| `sf-docker-config` | `.docker/config.json` | exact | block |
| `sf-aws-credentials` | `.aws/credentials` | exact | block |
| `sf-ssh-dir` | `.ssh/*` | glob | block |
| `sf-mobileprovision` | `*.mobileprovision` | glob | block |
| `sf-vault-json` | `vault.json` | basename | block |
| `sf-htpasswd` | `.htpasswd` | basename | block |

## Usage in Config

```toml
[sensitive_files]
disable_builtin = ["sf-dotenv-wildcard"]  # Allow .env.local but still block .env
extra_allow = [".env.example"]            # Path-level override
```
