# Architecture

The application is split into `ui`, `core`, `database`, `models`, and `utils`.

```text
UI ──> Core services ──> Process / hardware adapters
 │            │                    │
 │            │                    ├──> NetworkManager / iw (inventory)
 │            │                    ├──> dumpcap (owned live capture)
 │            │                    ├──> TShark / HCX (evidence analysis)
 │            │                    └──> Hashcat (bounded offline recovery)
 │            ├──> Scope manager ──> SQLite
 │            └──> Mock provider ──> synthetic fixtures
 └──> Plugins (profiles / parsers / reports)
```

- `ui` renders state and delegates to services; it contains no command construction.
- `core` owns process lifetime, inventory providers, authorization checks, and recovery planning.
- `core/laboratory.py` owns the capture/import/analyse/recover state machine. Every live or offline action checks the active project and BSSID before starting a child process.
- `core/lab_jobs.py` owns only the child process it started, applies timeouts, and sends an interrupt before forcefully stopping that child. It never searches for or terminates unrelated processes.
- `database` supplies SQLite models and a session factory.
- `models` defines typed records and status vocabulary.
- `utils` contains validation shared by services.

External commands are invoked with argument vectors only. `ProcessManager` and `ToolJob` track each child they start and stop only those children. Projects are the authorization boundary: discovered objects are not automatically in scope. Imported captures are copied into private artifact directories and checked against their recorded SHA-256 before analysis. HCX output is filtered to the authorized BSSID; Hashcat output is checked against the selected hash material before it is reported as recovered.

The UI uses background futures for hardware and tool work. It polls state on the Qt event loop, keeps errors next to their action, disables conflicting project changes while a lab job runs, and marks unfinished jobs as interrupted when the single application instance starts again.
