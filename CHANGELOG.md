# Changelog

## 0.2.0 - 2026-10-07

- Reworked the desktop workflow around projects, authorized targets, capture artifacts, evidence, and offline recovery.
- Added real `dumpcap` capture, PCAP/PCAPNG import, TShark analysis, HCX conversion, and bounded Hashcat dictionary jobs with cancellation and persisted results.
- Added SHA-256 capture integrity checks, BSSID scope filtering, recovery-result verification, single-instance locking, and interrupted-job recovery.
- Replaced the first-pass dark interface with a native Qt design system, visible focus states, accessible names, evidence panels, and explicit empty/error states.
- Redesigned Capturas into spaced sections and added automatic client discovery for the selected BSSID, including one directed reconnect option.
- Fixed live client parsing and added scrollable capture pages with dedicated evidence space for short windows.
- Preserved the capture result after interface refreshes, reported observed frame counts, and rejected directed reconnects with zero client ACKs instead of presenting them as confirmed.
- Added an automatic directed reconnect window during live capture for the single selected client.
- Increased the default live-capture window to 120 seconds and enforce that minimum when automatic reconnect is enabled.
- Added live Hashcat recovery telemetry in the UI: tested candidates, total keyspace, percentage, speed, and recovered-hash count.
- The network inventory now shows the radio band and distinguishes radio count from SSID-name count; BSSID remains the identity used for authorization and capture.
- The inventory uses NetworkManager's reported frequency when available, and capture analysis records peers, observed frequencies, association/authentication frames, and an evidence-based no-EAPOL diagnosis.
- Target selection warns when the same SSID exposes sibling radios, so the operator can verify the exact BSSID where the client is associated.
- Automatic capture now runs a second, BSSID-filtered PMKID/EAPOL method after the single directed reconnect; both attempts remain separate and auditable.
- Reconnect automation now prefers a locally managed client on the authorized BSSID before using the scoped monitor-client path.
- Diagnostics and the Debian package now check and include `pkexec`, required for explicit monitor-mode transitions.
- Job cancellation now terminates the complete child-process group, and progress-reader failures cannot interrupt a capture or recovery.
- Added an installable UI skills reference and documented the hardware validation boundary for production acceptance.

## 0.1.0 - 2026-10-06

- Initial public repository foundation, deterministic Mock Mode, scope controls,
  test automation, and Debian packaging scaffold.
