---
name: pair-phone
description: "Pair a phone with HermLink (the hermes_bridge mobile app): point the user at the /pair command; never handle the pairing secrets yourself."
version: 1.0.0
author: Valentin Nagacevschi
license: MIT
metadata:
  hermes:
    tags: [HermLink, pairing, mobile, QR]
---

# Pair a phone with HermLink

Use this when the user asks to pair, connect, or re-pair the HermLink phone app, asks for "the
pairing code" or "the QR", or says an invite expired.

## What to do

Tell the user to type the command themselves, in this chat or in the Hermes CLI:

    /pair

It mints a single-use invite (valid about an hour) and shows the pairing code with a QR. In the
terminal the QR is drawn inline; in a messaging app it arrives as an image. On the phone: open
HermLink → **Pair new device** → scan. Running it again mints a fresh invite and keeps the same
laptop profile and key, so it is also the fix for an expired invite or a second phone.

- `/pair --check` reports readiness (dependencies, allowlist, home channel, plugin enabled) without
  minting anything.
- `/pair` refuses group chats; the user has to send it in a direct message or the CLI.
- Outside Hermes, the same thing is `python3 ~/.hermes/plugins/hermes_bridge/pair.py`.
- After the very first pairing on a laptop, `hermes gateway restart` connects it.

## What not to do

The QR carries the invite token **and** the end-to-end encryption key. Anything you run or read
goes to the model provider as tool output, so:

- Do not run `pair.py` through a terminal tool, and do not read `~/.hermes/psk` or the
  `HERMES_BRIDGE_*` values in `~/.hermes/.env`.
- Do not repeat, rewrite, or summarize a pairing code, QR, or payload the user pastes to you.
  Tell them to delete it and run `/pair` again for a fresh invite.
