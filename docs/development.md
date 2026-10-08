# Development

Run `./scripts/install-kali.sh` to check the local environment, then `./scripts/dev.sh` or `./scripts/run.sh`. Both use real system data by default.

Use `WIFI_LAB_MOCK=1 WIFI_LAB_MOCK_SCENARIO=capture-valid ./scripts/dev.sh` for synthetic UI data. The demo database is separate from the real database. Diagnostics always query the actual host.

Run `./scripts/test.sh` before a pull request. Headless UI checks require `QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=basic` and an isolated temporary database.

Network discovery uses NetworkManager through `nmcli`; the initial query uses `--rescan no`. An explicit UI scan uses `--rescan yes`. Never describe this scan as a monitor-mode passive capture. System calls use argument arrays, a stable locale and bounded timeouts. The UI polls background futures on its Qt event loop.
