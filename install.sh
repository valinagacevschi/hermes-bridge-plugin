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

# --- pair-phone.sh: deploy alongside the plugin so re-pairing later doesn't
# need this repo/tarball again — it's self-contained (only touches
# $HERMES_HOME/.env + $HERMES_HOME/psk + the public relay). ---
cp "$SRC_ROOT/pair-phone.sh" "$PLUGIN_DEST/pair-phone.sh"
chmod +x "$PLUGIN_DEST/pair-phone.sh"

# --- Provisioning: use pre-set values, else self-serve from the relay ---
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

# `token` (a one-time phone-pairing invite) is only set when this run actually
# provisions — used below to decide whether to print the combined QR.
token=""

if [[ -f "$HERMES_ENV" ]] && grep -q "HERMES_BRIDGE_API_KEY" "$HERMES_ENV"; then
  echo "Laptop already provisioned ($HERMES_ENV has HERMES_BRIDGE_API_KEY) — skipping"
  echo "To pair a phone, run: $PLUGIN_DEST/pair-phone.sh"
elif [[ -n "${HERMES_BRIDGE_PROFILE_ID:-}" && -n "${HERMES_BRIDGE_API_KEY:-}" ]]; then
  # Bringing your own already-claimed credentials (e.g. restoring a previous
  # install) — write them directly, no self-serve call, no phone invite to
  # print (use pair-phone.sh after if you also need to re-pair a phone).
  {
    echo ""
    echo "HERMES_BRIDGE_RELAY_URL=${HERMES_BRIDGE_RELAY_URL:-$DEFAULT_RELAY_URL}"
    echo "HERMES_BRIDGE_PROFILE_ID=$HERMES_BRIDGE_PROFILE_ID"
    echo "HERMES_BRIDGE_API_KEY=$HERMES_BRIDGE_API_KEY"
  } >> "$HERMES_ENV"
  echo "Wrote pre-set env vars to $HERMES_ENV"
else
  # Self-serve provisioning — no admin/maintainer involved. Mints a profile +
  # laptop api_key + a one-time phone-pairing invite from the public relay.
  for cmd in curl jq qrencode xxd; do
    command -v "$cmd" >/dev/null || { echo "ERROR: $cmd not installed"; exit 1; }
  done

  echo ""
  ask relay_base "Relay URL [https://herelay.appcenter.ro]: " "https://herelay.appcenter.ro"
  relay_ws="${relay_base/https:/wss:}"
  relay_ws="${relay_ws/http:/ws:}"

  echo "Provisioning via $relay_base ..."
  RESP="$(curl -sf -X POST "$relay_base/api/pair/provision" -H "Content-Type: application/json" -d '{}')" \
    || { echo "ERROR: provisioning failed (relay unreachable or rate-limited)"; exit 1; }

  profile_id="$(jq -r '.profile_id' <<<"$RESP")"
  api_key="$(jq -r '.api_key' <<<"$RESP")"
  token="$(jq -r '.token' <<<"$RESP")"
  [[ -n "$profile_id" && "$profile_id" != "null" && -n "$api_key" && "$api_key" != "null" ]] \
    || { echo "ERROR: unexpected provision response: $RESP"; exit 1; }

  {
    echo ""
    echo "HERMES_BRIDGE_RELAY_URL=$relay_ws"
    echo "HERMES_BRIDGE_PROFILE_ID=$profile_id"
    echo "HERMES_BRIDGE_API_KEY=$api_key"
  } >> "$HERMES_ENV"
  echo "Provisioned profile $profile_id — wrote env vars to $HERMES_ENV"
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
  echo "PSK written to $PSK_FILE (chmod 600)"
fi

# Print the phone-pairing QR (invite token + PSK, combined so one scan does
# both). If provisioning was skipped above (already provisioned, or bring-
# your-own-credentials), `token` is unset here — fall back to pair-phone.sh,
# which mints a fresh invite for the existing profile.
if [[ -n "$token" && "$token" != "null" ]]; then
  PSK_HEX="$(xxd -p "$PSK_FILE" | tr -d '\n')"
  PAYLOAD="$(jq -cn --arg t "$token" --arg p "$PSK_HEX" '{token:$t, psk:$p}')"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Open Hermes Bridge on your phone -> Pair new device -> scan:"
  echo ""
  qrencode -t ANSIUTF8 "$PAYLOAD"
  echo "  Invite expires in 1 hour. If it lapses, re-run:"
  echo "    $PLUGIN_DEST/pair-phone.sh"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

echo ""
echo "Done. Start the gateway with:"
echo "  hermes gateway run"
