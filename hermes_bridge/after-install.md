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

Nothing else to run. The app's Agent screen (sessions, skills, cron, usage,
memory) reads Hermes through its local REST API, which lives in the dashboard
process rather than the gateway — so on startup the plugin starts Hermes' own
headless backend (`hermes serve` on 127.0.0.1:9119) whenever nothing already
serves it, as a child of the gateway that exits with it. Already run your own
`hermes dashboard`? It is left alone, and `HERMES_BRIDGE_API_PORT=<port>` in
`~/.hermes/.env` points the plugin at a non-default port.
`HERMES_BRIDGE_START_API=0` turns the auto-start off. It logs to
`~/.hermes/logs/hermes-bridge-api.log`.

`pair.py --check` reports all of the above without touching the relay.

The Runs and Approvals tabs need one more surface — Hermes' `/v1/runs` routes.
Set `platforms.api_server.enabled: true` in `~/.hermes/config.yaml` for those
two, then send one chat message to confirm replies still arrive: that setting
collided with an older version of this plugin, and the fix is not yet verified
on a live gateway. Every other tab works on the dashboard alone.

To upgrade later, reinstall with `--force`. `hermes plugins update` cannot
work here: this plugin installs from a subdirectory, so its directory holds no
`.git` for update to pull.

    hermes plugins install valinagacevschi/hermes-bridge-plugin/hermes_bridge --force

Requires Hermes 0.21.0 or newer.
