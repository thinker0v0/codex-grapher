#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root on the Hermes VPS." >&2
  exit 77
fi

profile_name="${1:-}"
case "$profile_name" in
  fin-global|fin-korea|hynix|business|oss|evaluator) ;;
  *)
    echo "Usage: $0 {fin-global|fin-korea|hynix|business|oss|evaluator}" >&2
    exit 64
    ;;
esac

env_path="/etc/hermes/${profile_name}.env"
account_name="hermes-${profile_name}"
getent group "$account_name" >/dev/null

read_secret() {
  local prompt="$1" value
  read -r -s -p "$prompt" value
  printf '\n' >&2
  printf '%s' "$value"
}

read_value() {
  local prompt="$1" value
  read -r -p "$prompt" value
  printf '%s' "$value"
}

provider="${HERMES_PROVIDER:-opencode-free}"
openai_api_key=""
dashscope_api_key=""
dashscope_base_url=""
case "$provider" in
  opencode-free) ;;
  openai-api)
    openai_api_key="$(read_secret 'OpenAI API key: ')"
    [[ -n "$openai_api_key" && "$openai_api_key" != *$'\n'* ]] || {
      echo "OpenAI API key must be non-empty and single-line." >&2; exit 65;
    }
    ;;
  alibaba)
    dashscope_api_key="$(read_secret 'Alibaba DashScope API key: ')"
    [[ -n "$dashscope_api_key" && "$dashscope_api_key" != *$'\n'* ]] || {
      echo "DashScope API key must be non-empty and single-line." >&2; exit 65;
    }
    dashscope_base_url="$(read_value 'DashScope base URL [https://dashscope-intl.aliyuncs.com/compatible-mode/v1]: ')"
    dashscope_base_url="${dashscope_base_url:-https://dashscope-intl.aliyuncs.com/compatible-mode/v1}"
    [[ "$dashscope_base_url" == https://* && "$dashscope_base_url" != *$'\n'* ]] || {
      echo "Base URL must be a single-line HTTPS URL." >&2; exit 65;
    }
    ;;
  *) echo "HERMES_PROVIDER must be opencode-free, openai-api, or alibaba" >&2; exit 64 ;;
esac

bot_token=""
app_token=""
allowed_users=""
allowed_channels=""
home_channel=""

if [[ "$profile_name" != evaluator ]]; then
  bot_token="$(read_secret 'Slack bot token (xoxb-...): ')"
  app_token="$(read_secret 'Slack app token (xapp-...): ')"
  allowed_users="$(read_value 'Allowed Slack member ID (U...): ')"
  allowed_channels="$(read_value 'Allowed Slack channel ID (C... or G...): ')"
  home_channel="$(read_value 'Home Slack channel ID (normally the same channel): ')"

  [[ "$bot_token" == xoxb-* ]] || { echo "Bot token must begin xoxb-." >&2; exit 65; }
  [[ "$app_token" == xapp-* ]] || { echo "App token must begin xapp-." >&2; exit 65; }
  [[ "$allowed_users" =~ ^U[A-Z0-9]+$ ]] || { echo "Member ID must begin U." >&2; exit 65; }
  [[ "$allowed_channels" =~ ^[CG][A-Z0-9]+$ ]] || { echo "Channel ID must begin C or G." >&2; exit 65; }
  [[ "$home_channel" =~ ^[CG][A-Z0-9]+$ ]] || { echo "Home channel ID must begin C or G." >&2; exit 65; }
fi

temp_file="$(mktemp /etc/hermes/.${profile_name}.env.XXXXXX)"
cleanup() { rm -f -- "$temp_file"; }
trap cleanup EXIT

umask 0077
{
  printf 'OPENAI_API_KEY=%s\n' "$openai_api_key"
  printf 'DASHSCOPE_API_KEY=%s\n' "$dashscope_api_key"
  printf 'DASHSCOPE_BASE_URL=%s\n' "$dashscope_base_url"
  printf 'SLACK_BOT_TOKEN=%s\n' "$bot_token"
  printf 'SLACK_APP_TOKEN=%s\n' "$app_token"
  printf 'SLACK_ALLOWED_USERS=%s\n' "$allowed_users"
  printf 'SLACK_ALLOWED_CHANNELS=%s\n' "$allowed_channels"
  printf 'SLACK_HOME_CHANNEL=%s\n' "$home_channel"
} >"$temp_file"

chown root:"$account_name" "$temp_file"
chmod 0640 "$temp_file"
mv -f -- "$temp_file" "$env_path"
trap - EXIT

echo "Credentials installed for ${profile_name} (${provider}); values were not printed."
echo "Run: systemctl restart hermes-profile@${profile_name}.service"
