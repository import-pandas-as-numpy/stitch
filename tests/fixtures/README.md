# EVTX fixtures

These fixtures are synthetic Windows Event Log files generated with the adjacent
`../weave` tool. They use fictional hostnames, example domains, and documentation
IP address ranges only.

Regenerate from the repository root:

```bash
PYTHONPATH=../weave python3 -m weave tests/fixtures/source/security-auth.jsonl tests/fixtures/evtx/security-auth.evtx --seed 1001
PYTHONPATH=../weave python3 -m weave tests/fixtures/source/system-services.jsonl tests/fixtures/evtx/system-services.evtx --seed 1002
PYTHONPATH=../weave python3 -m weave tests/fixtures/source/powershell-activity.jsonl tests/fixtures/evtx/powershell-activity.evtx --seed 1003
PYTHONPATH=../weave python3 -m weave tests/fixtures/source/sysmon-activity.jsonl tests/fixtures/evtx/sysmon-activity.evtx --seed 1004
PYTHONPATH=../weave python3 -m weave tests/fixtures/source/defender-operational.jsonl tests/fixtures/evtx/defender-operational.evtx --seed 1005
PYTHONPATH=../weave python3 -m weave tests/fixtures/source/wmi-activity.jsonl tests/fixtures/evtx/wmi-activity.evtx --seed 1006
PYTHONPATH=../weave python3 -m weave tests/fixtures/source/task-scheduler-operational.jsonl tests/fixtures/evtx/task-scheduler-operational.evtx --seed 1007
```

Fixture contents:

1. `security-auth.evtx`: successful and failed logons, explicit credentials,
   process creation, and special privileges across two synthetic workstations.
2. `system-services.evtx`: kernel boot and service-control events across two
   synthetic servers.
3. `powershell-activity.evtx`: PowerShell engine, module, and script block
   events for a synthetic workstation.
4. `sysmon-activity.evtx`: Sysmon process creation, network connection, file
   creation, and DNS query events across a synthetic workstation and server.
5. `defender-operational.evtx`: Microsoft Defender detection, remediation, and
   configuration-change events for synthetic workstations.
6. `wmi-activity.evtx`: WMI query and permanent consumer activity across a
   synthetic workstation and server.
7. `task-scheduler-operational.evtx`: scheduled task registration, update,
   action-start, and action-complete events.

The `collections/example-case` directory mirrors a small host-oriented case
folder. It intentionally contains copies of selected generated EVTX files so
recursive discovery can be tested against nested directories without changing
the event-provided computer and channel identities.

The `sigma` directory contains synthetic Sigma rules that hunt against the
generated EVTX fixtures using common Windows field names such as `Image`,
`DestinationIp`, `CONSUMER`, `ActionName`, and `Path`.

The `sigma-grammar` directory contains rules that exercise broader Sigma syntax
such as keyword searches, lists of map alternatives, wildcard values, `null`,
and condition lists.
