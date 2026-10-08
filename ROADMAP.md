# Roadmap

Implemented: NetworkManager inventory, native desktop workflow, scoped live capture with dumpcap, PCAP/PCAPNG import, TShark analysis, HCX conversion, bounded dictionary recovery with Hashcat, private artifact directories, persisted history and cancellation.

Before production acceptance:
- Validate live capture with the operator's authorized BSSID and adapter.
- Exercise monitor-mode transitions and capture permissions across supported drivers.
- Validate fresh package installation and upgrades on supported distributions.
- Add disk-retention management and explicit backup/export workflows for artifact history.

Future extensions: resumable recovery, additional bounded offline strategies and signed release automation.
