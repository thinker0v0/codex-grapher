# Credential Setup for Hermes, Slack, Qwen, and Codex

Status: frozen legacy procedure; do not execute in the active NQ cycle

> This document preserves historical Slack/profile credential instructions only.
> Hermes native Buzz is the sole final active surface, with routes `nomad`,
> `opensource`, `business`, and `hynix`; Slack and `fin-global` are frozen legacy.
> The current cycle forbids credentials, network/API setup, sudo, installation,
> deployment, service restart, staging, and real workers. A future explicitly
> authorized credential plan must be reviewed and rewritten for native Buzz before
> use. Nothing below is current operator instruction or release evidence.

Never paste API keys or Slack tokens into chat, Git, project files, shell
history, screenshots, or general logs. Enter them directly on the VPS. Tell the
operator agent only that installation is complete and provide non-secret IDs.

## 1. Recommended identity layout

Create five Slack apps and separate model credentials for:

| Profile | Slack app | Slack channel | VPS environment file |
|---|---|---|---|
| fin-global | Hermes Fin Global | hermes-fin-global | /etc/hermes/fin-global.env |
| fin-korea | Hermes Fin Korea | hermes-fin-korea | /etc/hermes/fin-korea.env |
| hynix | Hermes Hynix | hermes-hynix | /etc/hermes/hynix.env |
| business | Hermes Business | hermes-business | /etc/hermes/business.env |
| oss | Hermes OSS | hermes-oss | /etc/hermes/oss.env |
| evaluator | no Slack ingress | none | /etc/hermes/evaluator.env |

The evaluator gets its own model key but no Slack tokens. Do not reuse a Slack
app token or bot token across project profiles.

## 2. Create each Slack app

Repeat these steps for each of the five builder profiles.

1. Open https://api.slack.com/apps and select Create New App.
2. Select From an app manifest and choose the intended Slack workspace.
3. Copy config/slack-app-manifest.example.yaml, replace both PROJECT labels,
   paste it into Slack, review, and create the app.
4. Open Settings, then Basic Information, then App-Level Tokens. Generate a
   token named hermes-socket with connections:write. Copy the xapp token once.
5. Open Settings, then Install App, and install it to the workspace. Copy the
   Bot User OAuth Token beginning xoxb.
6. If scopes or event subscriptions are changed later, reinstall the app.
7. In Slack, invite only the matching bot to the matching channel.

The manifest enables the scopes and events Hermes v0.20.5 documents for channel
messages, direct messages, group messages, and attachments. Remove private
channel, DM, group-DM, or file scopes later if those features are not wanted.

### Find the allowlist IDs

- User ID: open the Slack profile, View full profile, More, Copy member ID. It
  begins with U.
- Channel ID: open channel details, About, and copy the channel ID. Public
  channels begin C; private channels and group DMs commonly begin G.

Record the IDs separately for each project. IDs are not authentication secrets,
but they still reveal workspace structure and should not be published.

## 3. Create Qwen credentials in Alibaba Cloud Model Studio

Use the international Alibaba Cloud account and the Singapore region.

1. Sign in to Alibaba Cloud and activate Model Studio model inference.
2. Select Singapore, region ap-southeast-1.
3. For strict isolation, create one workspace or RAM identity per profile,
   including evaluator.
4. Open Model Studio, API Key, Create API Key.
5. Use Custom permission where available. Restrict the model scope and allow
   only the public IPv4 address of your own VPS.
6. Copy the plaintext key immediately. New keys may only be shown once.
7. Record the matching Workspace ID if using a workspace-dedicated endpoint.

Current deployment uses pay-as-you-go credentials with:

    DASHSCOPE_BASE_URL=https://dashscope-intl.aliyuncs.com/compatible-mode/v1

Alibaba currently recommends the workspace-dedicated Singapore endpoint for
production:

    https://WORKSPACE_ID.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1

Do not mix pay-as-you-go, Token Plan, and Coding Plan keys or endpoints. Token
Plan keys begin sk-sp and require their Token Plan endpoint. Use a low spending
alert and benchmark before making a long subscription commitment.

## 4. Enter credentials on the VPS

Connect:

    ssh YOUR_ADMIN_USER@YOUR_VPS_HOST

Recommended: use the no-echo interactive helper deployed with the control
plane. It validates token and ID shapes and atomically installs a root-owned
profile file without putting secrets in shell history:

    /usr/local/libexec/ai-ops/configure-hermes-credentials oss

Use the matching profile name for later apps. Never paste its prompts or output
into chat. The manual method below remains available for recovery.

Edit one builder file at a time, for example:

    nano /etc/hermes/oss.env

Enter values without sharing them elsewhere:

    DASHSCOPE_API_KEY=REPLACE_ON_VPS
    DASHSCOPE_BASE_URL=https://dashscope-intl.aliyuncs.com/compatible-mode/v1
    SLACK_BOT_TOKEN=REPLACE_ON_VPS
    SLACK_APP_TOKEN=REPLACE_ON_VPS
    SLACK_ALLOWED_USERS=U0123456789
    SLACK_ALLOWED_CHANNELS=C0123456789
    SLACK_HOME_CHANNEL=C0123456789

Repeat for fin-global, fin-korea, hynix, business, and oss. The evaluator file
contains only its own DASHSCOPE_API_KEY and base URL; leave every Slack value
empty. Existing files are root-owned and group-readable only by their profile.

Do not put Slack Signing Secret into these files for the current Socket Mode
deployment. It becomes relevant only if the design later changes to inbound
HTTP request URLs.

## 5. Authenticate Codex workers

Codex authentication is separate from the Hermes Qwen credential.

Option A uses the existing ChatGPT/Codex account. Run device login separately
for each builder identity so each isolated CODEX_HOME receives its own auth
state. Example:

    runuser -u hermes-oss -- env HOME=/srv/hermes/oss CODEX_HOME=/srv/hermes/oss/.codex codex login --device-auth

Open the displayed URL on the laptop and enter the displayed one-time code.
Repeat with fin-global, fin-korea, hynix, business, and oss.

Option B uses OpenAI API billing. Create a project-scoped API key in the OpenAI
Platform and pipe it to codex login --with-api-key for the matching profile.
API billing is separate from a ChatGPT subscription. Never use an organization
Admin API key for a worker.

Check a profile without revealing credentials:

    runuser -u hermes-oss -- env HOME=/srv/hermes/oss CODEX_HOME=/srv/hermes/oss/.codex codex login status

## 6. Optional Z.AI benchmark credential

Do not install Z.AI into the production Hermes profiles yet. It remains a
benchmark candidate.

1. Sign in to the Z.AI Open Platform.
2. For ordinary Hermes API evaluation, create a general API key and use the
   general endpoint https://api.z.ai/api/paas/v4.
3. A GLM Coding Plan subscription uses the separate coding endpoint
   https://api.z.ai/api/coding/paas/v4 and is documented for supported coding
   tools only. Do not assume it authorizes arbitrary Hermes planner traffic.
4. Store the benchmark key in a separate root-only benchmark environment, not
   in a running Hermes profile, until provider compatibility is proven.

## 7. What to report back safely

Report only:

- Slack apps created: yes or no for each profile;
- env files populated: yes or no for each profile;
- Codex login status: logged in or not logged in for each builder;
- Alibaba plan type, region, and whether keys are project-separated;
- non-secret Slack User IDs and Channel IDs only if automated configuration is
  wanted;
- Z.AI benchmark account available: yes or no.

Never report the xoxb token, xapp token, model API key, OpenAI API key, device
access token, or full auth file.
