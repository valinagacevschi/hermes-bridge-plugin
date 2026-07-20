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

- **The short-code pairing protocol didn't require a plugin code change.** The
  Mac-side adapter's protocol (`HERMES_BRIDGE_PROFILE_ID`/`HERMES_BRIDGE_API_KEY` env
  vars, `?api_key=` on the WS URL, `Authorization: Bearer` on REST calls) was already
  compatible — claiming an invite just gets the phone the same `profile_id`/`api_key`
  that also has to go on the Mac. The actual gap was docs: README never said the two
  had to match. Fixed in the Access/Pairing sections.
