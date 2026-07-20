# AGENTS.md

## Lessons Learned

- **This repo is a public mirror, not the source.** Active plugin development happens
  in `expo-hermes` (private monorepo) at `plugins/platforms/hermes_bridge/`. Left
  un-synced, this repo silently drifts — that's how a "protocol mismatch" bug report
  turned out to be months of missing features (attachments, voice, streaming edits,
  cron RPCs, memory/skills write-approval), not an actual protocol change. Run
  `scripts/sync-from-expo-hermes.sh` after any change lands there, or trigger the
  (currently manual, token-gated) `sync hermes-bridge-plugin` CI job in expo-hermes.

- **Straight copy breaks the tests.** The monorepo uses `plugins.platforms.hermes_bridge.X`
  import paths and a real Hermes install to satisfy `gateway.platforms.base`/`tools.*`
  at test time; this repo uses `hermes_bridge.X` and has neither installed, so
  `tests/testutil.py` must fully stub them — real dataclasses for `SendResult`/
  `MessageEvent` (not `MagicMock()`, which discards constructor kwargs on attribute
  read), and a real (not `MagicMock()`) `tools` package object, since
  `from tools import write_approval` resolves via `getattr` first and a MagicMock
  parent never raises `AttributeError` to fall back to the real submodule. The sync
  script also has to reorder some source files' imports — `testutil` must run before
  the first `hermes_bridge`/`gateway` import, which the monorepo's own file order
  doesn't always guarantee (it doesn't need to, there — real Hermes is installed).

- **The short-code pairing protocol didn't require a plugin code change (at the time).**
  The Mac-side adapter's protocol (`HERMES_BRIDGE_PROFILE_ID`/`HERMES_BRIDGE_API_KEY` env
  vars, `?api_key=` on the WS URL, `Authorization: Bearer` on REST calls) was already
  compatible — claiming an invite just got the phone the same `profile_id`/`api_key`
  that also had to go on the Mac. Superseded within the same day by self-serve
  provisioning (below) — check current README/install.sh before trusting this as
  present-tense.

- **`install.sh`/`pair-phone.sh` are hand-maintained, but "no source to sync from" can
  stop being true overnight.** expo-hermes shipped self-serve pairing
  (`POST /api/pair/provision`, no `ADMIN_SECRET`) and a new `pair-phone.sh`, with a
  matching `install.sh` rewrite — real logic this repo needed, not just docs. Its
  `install.sh` had independently diverged too (this repo added `curl \| bash` +
  non-interactive env-var support the monorepo's copy never had), so this wasn't a
  pure-copy: had to merge monorepo's self-serve provisioning logic into this repo's
  curl\|bash-capable installer by hand, and add `pair-phone.sh` (a new bucket-1
  candidate — self-contained bash, only touches `$HERMES_HOME`/the relay, no
  monorepo-only paths). `scripts/sync-from-expo-hermes.sh` still only handles the
  Python package + its tests — it does not know about `install.sh`/`pair-phone.sh`.
  If they diverge again, that's a manual reconciliation, not a script run.
