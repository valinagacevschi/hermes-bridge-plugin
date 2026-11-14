# HermLink — two steps left

**1. Python dependencies.** Hermes ships `websockets`. This plugin also needs
PyNaCl (end-to-end encryption) and `qrcode` (the pairing QR in your terminal).

Hermes 0.21.0 and newer prepares those declared dependencies after you agree,
during install or enable. Answer yes when asked. Hermes selects its managed
environment; there is no generation path to type.

Older installations leave plugin dependencies uninstalled. Install them into
the Hermes venv yourself:

    ~/.hermes/hermes-agent/venv/bin/pip install "PyNaCl>=1.6,<1.7" "qrcode>=7.4,<8"

Skip `qrcode` and step 2 prints a payload string you cannot scan.

**2. Pair a phone.** The first run creates the profile, the laptop API key,
and the end-to-end key, then prints the QR. Run it again and it keeps that
profile and key, and mints a fresh invite:

    python3 ~/.hermes/plugins/hermes_bridge/pair.py

Then install **HermLink** from the App Store, tap *Pair new device*, and
scan. `pair.py` also points cron delivery at this chat
(`HERMES_BRIDGE_HOME_CHANNEL`) and allowlists the bridge's sender
(`HERMES_BRIDGE_ALLOWED_USERS=mobile`) — without it Hermes answers your first
message with "I don't recognize you yet" and a pairing code, because it
default-denies any sender with no allowlist configured. Answer *yes* to the enable prompt above, restart the gateway
(`hermes gateway restart`), and your agent is on your phone.

Re-run `pair.py` any time to pair another phone or replace an expired invite —
it reuses the same profile. Self-serve provisioning allows five requests per
client IP per hour; if that limit is reached, wait for the window to expire
before trying again.

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

**Pairing from inside Hermes: `/pair`.** Once the plugin is enabled, the same
thing is a slash command (Hermes 0.22.3 or newer; older Hermes answers with a
pointer back to `pair.py`):

- In the Hermes CLI (or a TUI/Desktop session) `/pair` prints the pairing code,
  the terminal QR, and the readiness report, like `pair.py`. `/pair --check`
  only reports. `/pair --verbose` adds the sensitive dump (API key, PSK, raw
  relay response) and is refused everywhere except a local session.
- In a direct message on a messaging gateway (Telegram, Discord, ...) `/pair`
  sends the QR as an image, the pairing code as text, and a warning that the
  image is a secret. It refuses group chats. The image file is written `0600`
  under `~/.hermes/cache/images/` and deleted after five minutes; the chat
  message itself stays until you delete it, so delete it once the phone is
  paired. Without `qrcode` it mints nothing and says how to fix it — the key
  is never sent as text.
- Only senders the gateway already authorizes can run it (unknown senders
  never reach a command). If several people can talk to your gateway, list
  yourself in `allow_admin_from` for that platform so only admins can run
  plugin commands such as `/pair`.

The QR carries the end-to-end key, so the trade-off is yours: a QR sent through
Telegram (or any third-party messenger) passes through, and may stay on, that
service's servers, and through any device signed in to the chat. Until the
invite is used (single use, about an hour), whoever scans the image first gets a
paired phone talking to your agent; after that it still holds the key that
decrypts traffic between this laptop and your phones. Prefer `/pair` in the CLI when
you are at the laptop; use the chat when you are not, delete the message after
scanning, and re-key (delete `~/.hermes/psk`, pair again, re-scan) if the image
went somewhere it should not have. Asking the agent in plain words ("pair my
phone") gets you pointed at `/pair`; the agent itself never handles the key.

The Runs and Approvals tabs need one more surface — Hermes' `/v1/runs` routes.
Set `platforms.api_server.enabled: true` in `~/.hermes/config.yaml` for those
two, then send one chat message to confirm replies still arrive: that setting
collided with an older version of this plugin, and the fix is not yet verified
on a live gateway. Every other tab works on the dashboard alone.

To upgrade a tracked install, including one installed from a subdirectory:

    hermes plugins update hermes_bridge

That reinstalls from the recorded source when the plugin directory has no
`.git`. If no source was recorded, force a reinstall instead. Either way
`~/.hermes/.env` and `~/.hermes/psk` stay put — updating does not re-pair.

    hermes plugins install valinagacevschi/hermes-bridge-plugin/hermes_bridge --force

Requires Hermes 0.21.0 or newer.
