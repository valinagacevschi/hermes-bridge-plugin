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

- [Hermes agent](https://github.com/NousResearch/hermes) **0.21.0 or newer** — the plugin
  registers itself as a platform named `hermes_bridge`, which needs the runtime plugin
  platform registry.
- **PyNaCl** and **qrcode** in the Hermes venv. `websockets` already ships with Hermes;
  these two do not, and Hermes never auto-installs plugin dependencies. PyNaCl does the
  encryption; `qrcode` draws the pairing QR (without it `pair.py` prints an unscannable
  payload string).

## Access

**Self-serve — no maintainer, no invite request, no admin secret.** `pair.py` calls the
relay's public `POST /api/pair/provision`, which mints your own isolated `profile_id` +
`hb_…` API key (rate-limited per IP) and a one-time phone-pairing invite in the same
response. There is nothing to request access to — pairing *is* signup.

The invite token is single-use and expires in 1 hour. Re-run `pair.py` any time to mint a
fresh invite for your *existing* profile — same script, no re-provisioning.

## Install

```bash
hermes plugins install valinagacevschi/hermes-bridge-plugin/hermes_bridge
~/.hermes/hermes-agent/venv/bin/pip install "PyNaCl>=1.6,<1.7" "qrcode>=7.4,<8"
python3 ~/.hermes/plugins/hermes_bridge/pair.py
hermes gateway restart
```

Answer **yes** to the installer's "Enable now?" prompt (that writes `plugins.enabled` for
you). The trailing `/hermes_bridge` is the plugin package inside this repo — install it
without the subdir and Hermes clones the whole repo, README included, which its plugin
security scanner flags.

Useful afterwards:

```bash
hermes plugins list                 # is it installed and enabled?
hermes plugins update hermes_bridge # pull the latest
hermes plugins doctor hermes_bridge # validate against the real runtime contracts
```

### Upgrading from the old `curl | bash` installer

Earlier versions shipped an `install.sh` that copied the plugin to
`~/.hermes/plugins/platforms/hermes_bridge`. Hermes derives the plugin key from that path,
so the old copy loads as `platforms/hermes_bridge` — a *different* plugin from the one
installed above. Once:

```bash
rm -rf ~/.hermes/plugins/platforms/hermes_bridge
# then drop the `platforms/hermes_bridge` entry from plugins.enabled in ~/.hermes/config.yaml
```

Your `~/.hermes/.env` credentials and `~/.hermes/psk` are untouched by any of this — the
same phone stays paired.

### Manual install

1. Copy `hermes_bridge/` → `~/.hermes/plugins/hermes_bridge/`.
2. `~/.hermes/hermes-agent/venv/bin/pip install "PyNaCl>=1.6,<1.7" "qrcode>=7.4,<8"`.
3. `hermes plugins enable hermes_bridge` (non-bundled plugins are opt-in).
4. `python3 ~/.hermes/plugins/hermes_bridge/pair.py`.
5. `hermes gateway restart`.

## Environment variables

Written by `pair.py` into `~/.hermes/.env`; listed in `hermes config` for inspection.

| Var | Value |
|-----|-------|
| `HERMES_BRIDGE_RELAY_URL` | `wss://herelay.appcenter.ro` (the hosted relay) |
| `HERMES_BRIDGE_PROFILE_ID` | minted by `pair.py` |
| `HERMES_BRIDGE_API_KEY` | minted by `pair.py` |

## Pairing your phone

1. Run `python3 ~/.hermes/plugins/hermes_bridge/pair.py` on the Mac — it provisions on
   first run and prints a QR holding the invite token + the encryption key.
2. Install the **Hermes Bridge** app from the App Store.
3. In the app: **Pair new device** → scan the QR.
4. `hermes gateway restart`.

Invite expired, or pairing a second phone to the same laptop? Run `pair.py` again — it
reuses your profile and prints a fresh QR.

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

## Reading the code comments

`hermes_bridge/` is transformed, not rewritten, from a private monorepo, so its comments
cite that repo's issue tracker and specs. The code is meant to stand on its own — this is
the legend for the references you'll hit, so a `(#41)` is context rather than a dead end.

| Ref | What it was |
|-----|-------------|
| `#38` | voice messages + TTS playback, end to end |
| `#40` | `supported_ops` capability handshake on the gateway WS |
| `#41` | buffered delivery, ordered replay, wake-poke for offline peers |
| `#42` | interactive controls — native buttons for approvals & clarify |
| `#44` | signed lifecycle webhooks → push notifications |
| `#45` | reaction ack lifecycle (received / processing / done) |
| `#46` | scheduled-task (cron) management screen |
| `#49` | `/rollback` + read-only memory/journey view |
| `#50` | turn-complete push dedup + category deep-links |
| `#62` | the `Platform('api_server')` collision — fixed, see below |
| `#64` | Agent-tab RPC auth against the dashboard REST (port + token caching) |

`PRD_Features.md` / `PRD_Bots.md` are that repo's private specs. `gateway/...` paths are
**Hermes core's** source, readable in any Hermes install — those are worth following.

`#62` is the one to know about historically: the adapter used to declare
`Platform('api_server')`, colliding with Hermes core's own api_server platform so replies
were delivered to the wrong adapter and silently dropped. It now registers as
`Platform("hermes_bridge")` (Hermes 0.21.0+), so the collision cannot happen and the old
"disable api_server first" workaround is gone.

## Troubleshooting

- **libsodium base64 variant** — the mobile side uses libsodium's `ORIGINAL` (standard)
  base64 variant, matching Python's `base64.b64encode`. A mismatch corrupts every frame
  cross-side. `crypto.py` uses standard base64 — keep it that way.
- **`:in` is a JSON envelope, `:out` is a raw sealed frame** — the relay forwards
  phone→agent as `{"role","content"}` where `content` is the sealed frame (json-decode
  then `open_frame(content)`); agent→phone replies are the bare sealed-frame string.
- **PSK QR is HEX, not base64** — `pair.py` encodes the PSK as 64 lowercase hex chars;
  the app expects hex (optionally wrapped as `{"psk":"<hex>"}`).
- **Plugin silently not loading** — non-bundled plugins under `~/.hermes/plugins/` are
  skipped unless listed in `config.yaml` under `plugins.enabled`. `hermes plugins list`
  shows the truth; `hermes plugins enable hermes_bridge` fixes it.
- **`No module named 'nacl'` in the gateway log** — PyNaCl is missing. Install it with the
  Hermes venv's pip (`~/.hermes/hermes-agent/venv/bin/pip`), not system pip.
- **Two copies loaded** — a leftover `~/.hermes/plugins/platforms/hermes_bridge` from the
  old installer registers under a different key. See *Upgrading*, above.
- **No QR printed, just a payload line** — `qrcode` is missing from the Hermes venv:
  `~/.hermes/hermes-agent/venv/bin/pip install "qrcode>=7.4,<8"`, then re-run `pair.py`
  (it mints a fresh invite and reprints, so an expired one costs nothing).
- **Start command** — `hermes gateway run` (foreground). If running as a service,
  restart atomically with `launchctl kickstart -k gui/$(id -u)/ai.hermes.gateway`.

## License

MIT — see [LICENSE](LICENSE).
