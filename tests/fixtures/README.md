# EVTX fixtures

These fixtures are synthetic Windows Event Log files. They use fictional
hostnames, example domains, and documentation IP address ranges only.

The source JSONL records are checked in under `tests/fixtures/source` so fixture
intent remains reviewable. The generated EVTX files are checked in because test
coverage needs real EVTX parser inputs.

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

The `correlation-evtx` directory contains EVTX files generated for correlation
tests. `sysmon-correlation.evtx` includes repeated `ProcessGuid` activity for
Sigma event-count correlation coverage.

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

The `sigma-correlation` directory contains multi-document Sigma rules that pair
base detections with event-count correlation documents.

The `sigma-syntax` directory contains parser-focused Sigma fixtures. The
`valid` subtree covers supported base-rule and correlation syntax. The `invalid`
subtree covers malformed YAML, base Sigma typos, missing selections, unsupported
modifiers, and malformed correlation definitions; tests load those files
individually so expected diagnostics remain deterministic.
