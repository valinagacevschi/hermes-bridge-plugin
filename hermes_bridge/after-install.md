# Hermes Bridge — two steps left

**1. Install PyNaCl** (Hermes ships `websockets` but not PyNaCl, and never
installs plugin dependencies for you):

    ~/.hermes/hermes-agent/venv/bin/pip install "PyNaCl>=1.6,<1.7"

**2. Pair a phone** — provisions your own profile on the relay, generates the
end-to-end key, prints the QR:

    python3 ~/.hermes/plugins/hermes_bridge/pair.py

Then install **Hermes Bridge** from the App Store, tap *Pair new device*, and
scan. Answer *yes* to the enable prompt above, restart the gateway
(`hermes gateway restart`), and your agent is on your phone.

Re-run `pair.py` any time to pair another phone or replace an expired invite —
it reuses the same profile.

Requires Hermes 0.21.0 or newer.
