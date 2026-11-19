"""Collectors package for ITShield.

Phase 6 collectors that gather system activity and publish it to the
Event Bus. Each collector implements the :class:`ModuleProtocol` so it
can be registered with the Core Manager.

Available collectors:
    * :class:`ProcessMonitor` - reads /proc on Linux, emits PROCESS_CREATED /
      PROCESS_TERMINATED events by diffing the snapshot.
    * :class:`NetworkMonitor` - reads /proc/net/{tcp,tcp6,udp,udp6}, emits
      NETWORK_CONNECTION events.

Future collectors (not yet implemented):
    * FileWatcher (inotify)   - lives in itshield.realtime
    * DNSMonitor              - parses /etc/resolv.conf output (needs
                                libpcap or eBPF for real DNS capture)
"""

from itshield.collectors.process_monitor import ProcessMonitor
from itshield.collectors.network_monitor import NetworkMonitor

__all__ = ["ProcessMonitor", "NetworkMonitor"]
