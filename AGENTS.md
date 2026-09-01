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

- **Installation is Hermes' job now — the hand-maintained installers are gone.** This repo
  used to ship `install.sh` (`curl | bash`: copy files, pip into the Hermes venv, append
  `plugins.enabled`, provision, print the QR) and `pair-phone.sh`. Hermes core already does
  all of the packaging half: `hermes plugins install <owner/repo[/subdir]>` clones,
  security-scans, prompts `requires_env`, prints `python_dependencies`, renders the plugin's
  `after-install.md`, writes `plugins.enabled` on a prompt, and takes capability consent.
  What was actually ours — provisioning + PSK + QR — became `hermes_bridge/pair.py` (stdlib
  only, synced from the monorepo like every other module).

- **Install by subdir: `valinagacevschi/hermes-bridge-plugin/hermes_bridge`.**
  `hermes plugins install` runs `tools/plugin_guard.py` on exactly the tree it installs, and
  the *repo root* scans CAUTION (this README documents a `curl` command) — blocked without
  `--force`. `hermes_bridge/` alone scans SAFE. Keep prose, fixtures, and anything with a
  `curl | sh` or `rm -rf` shaped string out of the package directory; the monorepo's test
  files scan DANGEROUS, which `--force` cannot override.

- **The sync script gates on Hermes' own validators.** After the tests, it runs
  `plugin_guard.scan_plugin` + `hermes_cli.plugin_dev.doctor_plugin` against `hermes_bridge/`
  and fails the sync if the tree would not install cleanly (skipped with a warning when no
  Hermes is installed locally). It also fails when the monorepo's `make_adapter` sets an
  adapter field this repo's `tests/testutil.py` doesn't — that drift used to surface as a
  bare `AttributeError` inside an unrelated handler.
