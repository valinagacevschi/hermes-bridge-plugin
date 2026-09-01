# Hermes Bridge — two steps left

**1. Install the two dependencies** (Hermes ships `websockets`, but neither of
these, and it never installs plugin dependencies for you):

    ~/.hermes/hermes-agent/venv/bin/pip install "PyNaCl>=1.6,<1.7" "qrcode>=7.4,<8"

PyNaCl does the end-to-end encryption; `qrcode` draws the pairing QR in your
terminal. Skip `qrcode` and step 2 prints a payload string you cannot scan.

**2. Pair a phone** — provisions your own profile on the relay, generates the
end-to-end key, prints the QR:

    python3 ~/.hermes/plugins/hermes_bridge/pair.py

Then install **Hermes Bridge** from the App Store, tap *Pair new device*, and
scan. `pair.py` also points cron delivery at this chat
(`HERMES_BRIDGE_HOME_CHANNEL`) and allowlists the bridge's sender
(`HERMES_BRIDGE_ALLOWED_USERS=mobile`) — without it Hermes answers your first
message with "I don't recognize you yet" and a pairing code, because it
default-denies any sender with no allowlist configured. Answer *yes* to the enable prompt above, restart the gateway
(`hermes gateway restart`), and your agent is on your phone.

Re-run `pair.py` any time to pair another phone or replace an expired invite —
it reuses the same profile.

To upgrade later, reinstall with `--force`. `hermes plugins update` cannot
work here: this plugin installs from a subdirectory, so its directory holds no
`.git` for update to pull.

    hermes plugins install valinagacevschi/hermes-bridge-plugin/hermes_bridge --force

Requires Hermes 0.21.0 or newer.
