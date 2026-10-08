# Plugin system

Plugins belong in `plugins/vendor_profiles`, `plugins/parsers`, or `plugins/reports`. Each plugin requires structured metadata: name, version, author, and supported application version. Plugins must not execute arbitrary shell input; external command execution remains validated in core services.
