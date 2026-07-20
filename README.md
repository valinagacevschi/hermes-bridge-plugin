# Hermes Bridge Plugin

A [Hermes](https://github.com/NousResearch/hermes) gateway plugin that connects your
local Hermes agent to the **Hermes Bridge** mobile app over an end-to-end-encrypted
relay. Chat with your agent from your phone; trigger it on a schedule and get the reply
pushed to you — even when the app is closed.

```
┌─────────────┐   sealed frames    ┌───────────────┐   sealed frames   ┌───────────┐
│ Hermes      │◀──────wss─────────▶│ Hermes Bridge │◀─────SSE/wss─────▶│  mobile   │
│ agent       │   (this plugin)    │  cloud relay  │                   │   app     │
│ (your Mac)  │                    │  (hosted)     │                   │ (iOS)     │
└─────────────┘                    └───────────────┘                   └───────────┘
        the relay only ever sees ciphertext — it can't read your messages
```

This repo is **only the plugin** — the code that runs inside *your* Hermes install. The
relay is a hosted service and the app ships via the App Store; this is the open, auditable
piece so you can see exactly what leaves your machine.

## End-to-end encryption

Messages are sealed with **XChaCha20-Poly1305** before they ever hit the network. The
32-byte pre-shared key (PSK) lives only on your machine and your phone — it is **never
sent to the relay**. The relay stores and forwards opaque ciphertext.

- Wire frame: `base64( 0x01 || nonce(24) || ciphertext )`
- AAD binds each frame to its `profile_id` and direction (`in`/`out`), preventing
  reflection and cross-profile replay.
- `hermes_bridge/crypto.py` (PyNaCl) is byte-for-byte compatible with the mobile app's
  crypto. The known-answer vector in `tests/test_crypto.py` guards that interop.

## Requirements

- A working [Hermes agent](https://github.com/NousResearch/hermes) install (this plugin
  loads into it and imports its `gateway.platforms.base`).
- Python 3.9+ with `websockets` and `PyNaCl` (installed into the Hermes venv by the
  installer).
- `curl`, `jq`, `qrencode`, `xxd` — used by `install.sh`/`pair-phone.sh` to self-serve a
  pairing from the relay and print the QR (`brew install jq qrencode`; curl/xxd ship with
  macOS).

## Access

**Self-serve — no maintainer, no invite request, no admin secret.** `install.sh` calls the
relay's public `POST /api/pair/provision` itself, which mints your own isolated
`profile_id` + `hb_…` API key (`tenant_selfserve`, rate-limited per IP) and a one-time
phone-pairing invite in the same response. There's nothing to request access to — running
the installer *is* signup.

The invite token is single-use and expires in 1 hour. If it lapses before you scan it (or
you want to pair a second phone later), re-run the `pair-phone.sh` the installer drops next
to the plugin — it mints a fresh invite for your *existing* profile, no re-provisioning.

## Install

One-liner (downloads + installs; prompts on the terminal):

```bash
curl -fsSL https://raw.githubusercontent.com/valinagacevschi/hermes-bridge-plugin/main/install.sh | bash
```

Non-interactive — pre-set your own already-claimed credentials to skip self-serve
provisioning entirely (e.g. restoring a previous install):

```bash
curl -fsSL https://raw.githubusercontent.com/valinagacevschi/hermes-bridge-plugin/main/install.sh \
  | HERMES_BRIDGE_PROFILE_ID=profile_ss_xxxx HERMES_BRIDGE_API_KEY=hb_… bash
```

Or from a checkout:

```bash
git clone https://github.com/valinagacevschi/hermes-bridge-plugin.git
cd hermes-bridge-plugin
./install.sh
```

`install.sh` copies the `hermes_bridge/` package + `pair-phone.sh` into
`~/.hermes/plugins/platforms/hermes_bridge/` (downloading a release tarball first when run
via `curl`), installs the Python deps into the Hermes venv, enables the plugin in
`~/.hermes/config.yaml`, self-serve provisions a profile/API key (see Access, above),
generates a PSK, and prints one combined QR (invite token + PSK) to scan on the phone.

### Manual install

1. Copy `hermes_bridge/` → `~/.hermes/plugins/platforms/hermes_bridge/`.
2. `~/.hermes/hermes-agent/venv/bin/pip install -r requirements.txt`.
3. Add to `~/.hermes/config.yaml` (non-bundled plugins require explicit opt-in):
   ```yaml
   plugins:
     enabled:
       - platforms/hermes_bridge
   ```
4. `curl -sf -X POST https://herelay.appcenter.ro/api/pair/provision -d '{}'` and write the
   returned `profile_id`/`api_key` (below) into `~/.hermes/.env`, alongside
   `HERMES_BRIDGE_RELAY_URL=wss://herelay.appcenter.ro`.
5. Generate a 32-byte PSK at `~/.hermes/psk` (`chmod 600`).
6. Combine the response's `token` + the PSK hex into `{"token":"...","psk":"..."}` and scan
   that on the phone (or run `pair-phone.sh` once step 4/5 are done, to do this for you).

## Environment variables

| Var | Value |
|-----|-------|
| `HERMES_BRIDGE_RELAY_URL` | `wss://herelay.appcenter.ro` (the hosted relay) |
| `HERMES_BRIDGE_PROFILE_ID` | from self-serve provisioning (see Access, above) |
| `HERMES_BRIDGE_API_KEY` | from self-serve provisioning (see Access, above) |

## Pairing your phone

1. Run `install.sh` on the Mac — it self-serve provisions and prints a combined QR
   (invite token + PSK).
2. Install the **Hermes Bridge** app from the App Store.
3. In the app: **Pair new device** → scan the QR.
4. Start the gateway: `hermes gateway run`.

Invite expired, or pairing a second phone to the same laptop? Run
`~/.hermes/plugins/platforms/hermes_bridge/pair-phone.sh` — it mints a fresh invite for
your existing profile and reprints the QR, no re-provisioning.

Your agent's replies now reach the phone; scheduled/cron outputs arrive as push
notifications with a durable inbox so nothing is lost while the app is closed.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
python tests/test_crypto.py                                                    # crypto interop (standalone script)
python -m pytest tests/test_rpc.py tests/test_streaming.py tests/test_attachments.py
```

The tests run **without** a Hermes install: `test_crypto.py` imports `crypto.py` directly
(PyNaCl only), and the other three stub `gateway.platforms.base`/`tools.*` via
`tests/testutil.py`.

## Troubleshooting

- **libsodium base64 variant** — the mobile side uses libsodium's `ORIGINAL` (standard)
  base64 variant, matching Python's `base64.b64encode`. A mismatch corrupts every frame
  cross-side. `crypto.py` uses standard base64 — keep it that way.
- **`:in` is a JSON envelope, `:out` is a raw sealed frame** — the relay forwards
  phone→agent as `{"role","content"}` where `content` is the sealed frame (json-decode
  then `open_frame(content)`); agent→phone replies are the bare sealed-frame string.
- **PSK QR is HEX, not base64** — the installer encodes the PSK as 64 lowercase hex chars
  (`xxd -p`); the app expects hex (optionally wrapped as `{"psk":"<hex>"}`).
- **Plugin silently not loading** — non-bundled plugins under `~/.hermes/plugins/` are
  skipped unless listed in `config.yaml` under `plugins.enabled`.
- **Install into the Hermes venv, not system pip** — use
  `~/.hermes/hermes-agent/venv/bin/pip`, or the import fails at runtime.
- **Start command** — `hermes gateway run` (foreground). If running as a service,
  restart atomically with `launchctl kickstart -k gui/$(id -u)/ai.hermes.gateway`.

## License

MIT — see [LICENSE](LICENSE).
