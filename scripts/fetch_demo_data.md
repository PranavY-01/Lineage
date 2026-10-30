# Real-data demo files

Lineage's tests use synthetic fixtures only. To try it on real Sysmon telemetry, download
these two samples from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-licensed;
never copy them into this repository):

| File | What it records |
|---|---|
| `Execution/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx` | A Meterpreter reverse TCP shell launched from an MSI package |
| `Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx` | A remote shell over a named pipe (Sysmon events 17 and 18) |

Keep them outside the repository, for example in `../lineage-data/`, then run:

```bash
lineage validate ../lineage-data/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx
lineage analyze ../lineage-data/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx --hot-only
lineage analyze ../lineage-data/lm_sysmon_18_remshell_over_namedpipe.evtx
```

Screenshots from these files can be made with
`python scripts/capture_screenshots.py --hero PATH --secondary PATH --inspect TARGET`; name
the sample under each image.

Further reading: the [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
project publishes larger recorded attack scenarios with Sysmon telemetry in JSON form.
