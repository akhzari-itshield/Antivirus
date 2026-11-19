"""GUI package for ITShield (PySide6).

The GUI is intentionally minimal at this stage:
    * shows Core status (refreshed from the IPC client)
    * lets the user pick a file/folder and trigger a scan
    * shows per-file results in a table

Phase 1-5 GUI scope (section 14 of the architecture document):
    - display Core state and module health
    - run a scan via the local Scanner (not yet via IPC; scan.request is
      still SCANNER_NOT_IMPLEMENTED on the IPC side)
    - view per-file results

A future version will route scan requests through IPC once the Scan Manager
is wired up.
"""
