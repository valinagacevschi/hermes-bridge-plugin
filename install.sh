#!/usr/bin/env bash
# Install the Hermes Bridge plugin into the local Hermes agent.
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
# The installable package lives in the hermes_bridge/ subdir; the repo root also
# holds README/LICENSE/tests which must NOT be copied into the Hermes plugin dir.
PLUGIN_SRC="$REPO_ROOT/hermes_bridge"
PLUGIN_DEST="$HERMES_HOME/plugins/platforms/hermes_bridge"
VENV_PIP="$HERMES_HOME/hermes-agent/venv/bin/pip"
HERMES_ENV="$HERMES_HOME/.env"
HERMES_CONFIG="$HERMES_HOME/config.yaml"

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
"$VENV_PIP" install -r "$REPO_ROOT/requirements.txt" --quiet

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

# Prompt for env vars if not already set.
if [[ -f "$HERMES_ENV" ]] && grep -q "HERMES_BRIDGE_RELAY_URL" "$HERMES_ENV"; then
  echo "Env vars already in $HERMES_ENV — skipping"
else
  echo ""
  read -rp "Relay WebSocket URL [ws://localhost:8082]: " relay_url
  relay_url="${relay_url:-ws://localhost:8082}"

  read -rp "Profile ID (e.g. work-macbook): " profile_id
  if [[ -z "$profile_id" ]]; then
    echo "ERROR: profile_id is required"
    exit 1
  fi

  echo "" >> "$HERMES_ENV"
  echo "HERMES_BRIDGE_RELAY_URL=$relay_url" >> "$HERMES_ENV"
  echo "HERMES_BRIDGE_PROFILE_ID=$profile_id" >> "$HERMES_ENV"
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
