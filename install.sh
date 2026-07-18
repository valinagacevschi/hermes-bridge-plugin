#!/usr/bin/env bash
# Install the Hermes Bridge plugin into the local Hermes agent.
#
# Two ways to run:
#   1. From a checkout:   ./install.sh
#   2. Straight from the web:
#        curl -fsSL https://raw.githubusercontent.com/valinagacevschi/hermes-bridge-plugin/main/install.sh | bash
#
# Non-interactive (e.g. CI, or to skip the prompts) — pre-set any of:
#   HERMES_BRIDGE_RELAY_URL  HERMES_BRIDGE_PROFILE_ID  HERMES_BRIDGE_API_KEY
#        curl -fsSL .../install.sh | HERMES_BRIDGE_PROFILE_ID=me HERMES_BRIDGE_API_KEY=hb_… bash
set -euo pipefail

REPO_SLUG="valinagacevschi/hermes-bridge-plugin"
REPO_REF="${HERMES_BRIDGE_REF:-main}"
DEFAULT_RELAY_URL="wss://herelay.appcenter.ro"

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PLUGIN_DEST="$HERMES_HOME/plugins/platforms/hermes_bridge"
VENV_PIP="$HERMES_HOME/hermes-agent/venv/bin/pip"
HERMES_ENV="$HERMES_HOME/.env"
HERMES_CONFIG="$HERMES_HOME/config.yaml"

# --- Resolve the source: local checkout if present, else download the tarball ---
# Under `curl | bash` there's no script file on disk, so BASH_SOURCE won't point
# at a checkout — fall back to downloading a pinned tarball.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [[ -n "$SELF_DIR" && -d "$SELF_DIR/hermes_bridge" ]]; then
  SRC_ROOT="$SELF_DIR"
else
  command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required"; exit 1; }
  command -v tar  >/dev/null 2>&1 || { echo "ERROR: tar is required";  exit 1; }
  echo "Downloading $REPO_SLUG ($REPO_REF)…"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  curl -fsSL "https://github.com/$REPO_SLUG/archive/refs/heads/$REPO_REF.tar.gz" \
    | tar -xz -C "$TMP_DIR"
  SRC_ROOT="$TMP_DIR/hermes-bridge-plugin-$REPO_REF"
fi
PLUGIN_SRC="$SRC_ROOT/hermes_bridge"
REQ_FILE="$SRC_ROOT/requirements.txt"

echo "Installing Hermes Bridge plugin → $PLUGIN_DEST"
mkdir -p "$PLUGIN_DEST"
cp -r "$PLUGIN_SRC"/. "$PLUGIN_DEST/"

# Use the hermes-agent virtualenv pip, not the system pip.
if [[ ! -x "$VENV_PIP" ]]; then
  echo "ERROR: Hermes venv not found at $VENV_PIP"
  echo "  Is hermes-agent installed? Expected path: $HERMES_HOME/hermes-agent/venv/"
  exit 1
fi
echo "Installing Python dependencies via hermes venv..."
"$VENV_PIP" install -r "$REQ_FILE" --quiet

# Enable the plugin in config.yaml (non-bundled plugins require explicit opt-in).
if [[ -f "$HERMES_CONFIG" ]]; then
  if grep -q "platforms/hermes_bridge" "$HERMES_CONFIG"; then
    echo "Plugin already listed in $HERMES_CONFIG — skipping"
  else
    echo "" >> "$HERMES_CONFIG"
    echo "plugins:" >> "$HERMES_CONFIG"
    echo "  enabled:" >> "$HERMES_CONFIG"
    echo "    - platforms/hermes_bridge" >> "$HERMES_CONFIG"
    echo "Added platforms/hermes_bridge to plugins.enabled in $HERMES_CONFIG"
  fi
else
  echo "WARNING: $HERMES_CONFIG not found — add manually:"
  echo "  plugins:"
  echo "    enabled:"
  echo "      - platforms/hermes_bridge"
fi

# --- Env vars: use pre-set values, else prompt on the terminal ---
# Reads come from /dev/tty so prompting still works under `curl | bash` (where
# stdin is the piped script, not the keyboard).
ask() {  # ask <var-name> <prompt> <default>
  local __var="$1" __prompt="$2" __default="${3:-}" __ans=""
  # Try the terminal; silently fall back to the default when there's no usable
  # tty (e.g. a fully non-interactive `curl | bash` with no controlling terminal).
  # `2>/dev/null` MUST precede `< /dev/tty`: bash applies redirects left-to-right,
  # so silencing stderr first suppresses the "Device not configured" message when
  # opening the tty fails (no controlling terminal).
  if [[ -r /dev/tty ]]; then
    read -rp "$__prompt" __ans 2>/dev/null < /dev/tty || __ans=""
  fi
  printf -v "$__var" '%s' "${__ans:-$__default}"
}

if [[ -f "$HERMES_ENV" ]] && grep -q "HERMES_BRIDGE_RELAY_URL" "$HERMES_ENV"; then
  echo "Env vars already in $HERMES_ENV — skipping"
else
  relay_url="${HERMES_BRIDGE_RELAY_URL:-}"
  [[ -z "$relay_url" ]] && ask relay_url "Relay WebSocket URL [$DEFAULT_RELAY_URL]: " "$DEFAULT_RELAY_URL"

  profile_id="${HERMES_BRIDGE_PROFILE_ID:-}"
  [[ -z "$profile_id" ]] && ask profile_id "Profile ID: " ""
  if [[ -z "$profile_id" ]]; then
    echo "ERROR: profile_id is required (set HERMES_BRIDGE_PROFILE_ID or run interactively)"
    exit 1
  fi

  api_key="${HERMES_BRIDGE_API_KEY:-}"
  [[ -z "$api_key" ]] && ask api_key "API key (hb_…), blank if pairing later: " ""

  {
    echo ""
    echo "HERMES_BRIDGE_RELAY_URL=$relay_url"
    echo "HERMES_BRIDGE_PROFILE_ID=$profile_id"
    [[ -n "$api_key" ]] && echo "HERMES_BRIDGE_API_KEY=$api_key"
  } >> "$HERMES_ENV"
  echo "Wrote env vars to $HERMES_ENV"
fi

# Generate the E2E PSK if not already present.
# The PSK is a stable 32-byte secret that must also be loaded on the phone.
# It is NEVER transmitted to the relay — only exchanged out-of-band (QR / display).
PSK_FILE="$HERMES_HOME/psk"
if [[ -f "$PSK_FILE" ]]; then
  echo "PSK already exists at $PSK_FILE — skipping generation"
else
  echo ""
  echo "Generating E2E PSK (32 random bytes)..."
  python3 -c "import os, sys; sys.stdout.buffer.write(os.urandom(32))" > "$PSK_FILE"
  chmod 600 "$PSK_FILE"
  PSK_HEX=$(xxd -p "$PSK_FILE" | tr -d '\n')
  echo "PSK written to $PSK_FILE (chmod 600)"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  IMPORTANT: Store this PSK on your phone (one-time setup)"
  echo ""
  echo "  PSK hex: $PSK_HEX"
  echo ""
  if command -v qrencode >/dev/null 2>&1; then
    echo "  Scan with the Hermes mobile app:"
    qrencode -t ANSIUTF8 "$PSK_HEX"
  else
    echo "  (Install qrencode for a scannable QR: brew install qrencode)"
    echo "  Then re-run this script, or manually enter the hex above in the app."
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

echo ""
echo "Done. Start the gateway with:"
echo "  hermes gateway run"
