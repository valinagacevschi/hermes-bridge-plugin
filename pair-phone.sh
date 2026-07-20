#!/usr/bin/env bash
#
# pair-phone.sh — re-pair a phone to an already-provisioned laptop bridge.
#
# install.sh provisions the laptop (profile + api_key) and prints a one-time
# QR, but that invite expires after 1 hour. Run this script anytime to mint a
# fresh invite for the SAME profile and reprint the {token, psk} QR — no
# re-provisioning, no ADMIN_SECRET, no owner involvement.
#
# Requires: curl, jq, qrencode, xxd. Reads HERMES_BRIDGE_PROFILE_ID and the
# PSK from ~/.hermes (written by install.sh).

set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
HERMES_ENV="$HERMES_HOME/.env"
PSK_FILE="$HERMES_HOME/psk"

for cmd in curl jq qrencode xxd; do
  command -v "$cmd" >/dev/null || { echo "error: $cmd not installed" >&2; exit 1; }
done

[[ -f "$HERMES_ENV" ]] || { echo "error: $HERMES_ENV not found — run install.sh first" >&2; exit 1; }
[[ -f "$PSK_FILE" ]] || { echo "error: $PSK_FILE not found — run install.sh first" >&2; exit 1; }

PROFILE_ID="$(grep -E '^HERMES_BRIDGE_PROFILE_ID=' "$HERMES_ENV" | cut -d= -f2- || true)"
[[ -n "$PROFILE_ID" ]] || { echo "error: HERMES_BRIDGE_PROFILE_ID not set in $HERMES_ENV" >&2; exit 1; }

RELAY_WS="$(grep -E '^HERMES_BRIDGE_RELAY_URL=' "$HERMES_ENV" | cut -d= -f2- || true)"
RELAY_URL="${RELAY_WS/wss:/https:}"
RELAY_URL="${RELAY_URL/ws:/http:}"
RELAY_URL="${RELAY_URL:-https://herelay.appcenter.ro}"

PSK_HEX="$(xxd -p "$PSK_FILE" | tr -d '\n')"
[[ "${#PSK_HEX}" -eq 64 ]] || { echo "error: $PSK_FILE is not 32 bytes" >&2; exit 1; }

RESP="$(curl -sf -X POST "$RELAY_URL/api/pair/provision" \
  -H "Content-Type: application/json" \
  -d "$(jq -cn --arg p "$PROFILE_ID" '{profile_id:$p}')")" \
  || { echo "error: invite creation failed (relay unreachable or rate-limited)" >&2; exit 1; }

TOKEN="$(jq -r '.token' <<<"$RESP")"
EXPIRES="$(jq -r '.expires_at' <<<"$RESP")"
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || { echo "error: no token in response: $RESP" >&2; exit 1; }

PAYLOAD="$(jq -cn --arg t "$TOKEN" --arg p "$PSK_HEX" '{token:$t, psk:$p}')"

echo
echo "Profile:  $PROFILE_ID"
echo "Invite:   $TOKEN  (single use, expires $EXPIRES)"
echo
echo "Open Hermes Bridge on your phone -> Pair new device -> scan:"
echo
qrencode -t ANSIUTF8 "$PAYLOAD"
echo
echo "QR contains the invite token AND the encryption key — keep this screen private until scanned."
