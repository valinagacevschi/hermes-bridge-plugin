# Hermes Bridge — three steps left

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

**3. Leave the dashboard running** — the app's Agent screen (sessions, skills,
cron, runs, approvals, usage, memory) reads Hermes through its local REST API,
which lives in the dashboard process, not the gateway:

    hermes dashboard --no-open

Chat works without it; the Agent screen shows `hermes_offline` on every tab
until it runs. **It is a foreground process, not a service** — a closed
terminal, a Ctrl-C or a dropped SSH session takes it down with SIGHUP and the
Agent screen fails again. Keep it alive with a launchd agent (macOS) or a
systemd unit, or at minimum `nohup ... &` plus `disown`. Pinning `--port 9119`
means the plugin finds it without relying on process discovery.

Already running on a non-default port and still offline? Add
`HERMES_BRIDGE_API_PORT=<port>` to `~/.hermes/.env`. `pair.py --check` reports
this and everything else above without touching the relay.

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
