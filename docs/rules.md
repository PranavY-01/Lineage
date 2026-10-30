# Rules

Lineage ships 20 event rules and 4 graph heuristics. This file is built from the rule files and the graph heuristics by `scripts/build_docs.py`; do not edit it by hand.

Technique and tactic mappings follow **MITRE ATT&CK v20 (Enterprise)** and are advisory: a finding is a lead for an analyst, not proof of a technique. Every ID below was checked against the ATT&CK website for this version.

## Summary

| ID | Kind | Title | Severity | Events | ATT&CK | Tactics |
|---|---|---|---|---|---|---|
| CMD-001 | event | Encoded PowerShell command | medium | 1 | T1059.001, T1027.010 | Execution, Stealth |
| CMD-002 | event | PowerShell download cradle | high | 1 | T1059.001, T1105 | Execution, Command and Control |
| CMD-003 | event | Certutil download or decode | high | 1 | T1105, T1140 | Command and Control, Stealth |
| CMD-004 | event | Mshta remote or inline script | high | 1 | T1218.005 | Stealth |
| CMD-005 | event | Regsvr32 remote scriptlet | high | 1 | T1218.010 | Stealth |
| CMD-006 | event | Recovery inhibited | high | 1 | T1490 | Impact |
| CMD-007 | event | Event log cleared | high | 1 | T1685.005 | Defense Impairment |
| CRD-001 | event | LSASS memory access | high | 10 | T1003.001 | Credential Access |
| CRD-002 | event | LSASS dump via command line | high | 1 | T1003.001 | Credential Access |
| GR-001 | graph | Office-descended process connected out | high | 1, 3 | T1204.002 | Execution |
| GR-002 | graph | Discovery burst | medium | 1 | T1033, T1082, T1016, T1087, T1482, T1057 | Discovery |
| GR-003 | graph | Dropped file later executed | medium | 1, 11 | T1105 | Command and Control |
| GR-004 | graph | Active process with no creation record | info | 1 | none | none |
| INJ-001 | event | Remote thread created in another process | medium | 8 | T1055 | Stealth, Privilege Escalation |
| LIN-001 | event | Office application spawned an interpreter | high | 1 | T1204.002 | Execution |
| LIN-002 | event | Script host spawned a shell | medium | 1 | T1059.005, T1059.007 | Execution |
| LIN-003 | event | WMI provider host spawned a shell | high | 1 | T1047 | Execution |
| LOC-001 | event | Execution from a user-writable staging path | low | 1 | none | Execution |
| LOC-002 | event | System binary name outside system directories | high | 1 | T1036.005 | Stealth |
| NET-001 | event | Proxy-execution binary made a network connection | high | 3 | T1218, T1105 | Stealth, Command and Control |
| PER-001 | event | Registry Run key set | medium | 13 | T1547.001 | Persistence |
| PER-002 | event | Scheduled task created | medium | 1 | T1053.005 | Persistence, Execution |
| PER-003 | event | Service created | medium | 1, 13 | T1543.003 | Persistence |
| PER-004 | event | File written to a Startup folder | medium | 11 | T1547.001 | Persistence |

## CMD-001 · Encoded PowerShell command

- Kind: event; severity: medium; needs events: 1.
- ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell; [T1027.010](https://attack.mitre.org/techniques/T1027/010/) Obfuscated Files or Information: Command Obfuscation.
- Tactics: Execution, Stealth.
- Matches: event 1; `encoded_command_present` is `true`.
- Why it matters: Passing a base64-encoded script hides the command from casual review and from naive command-line matching; it is common in loaders and rare in hand-written admin work.
- Known false positives: Management agents and installers that pass scripts as encoded commands.

## CMD-002 · PowerShell download cradle

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell; [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer.
- Tactics: Execution, Command and Control.
- Matches: event 1; `image_name` is `powershell.exe` or `pwsh.exe`; `command_line_full` contains `downloadstring` or `downloadfile` or `downloaddata` or `invoke-webrequest` or `invoke-restmethod` or `net.webclient` or `start-bitstransfer`.
- Why it matters: PowerShell fetching remote content in one command is a common first-stage loader pattern; admin scripts rarely download and run code inline.
- Known false positives: Admin or bootstrap scripts that download modules or installers inline.

## CMD-003 · Certutil download or decode

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer; [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode Files or Information.
- Tactics: Command and Control, Stealth.
- Matches: event 1; `image_name` is `certutil.exe`; `command_line` contains `urlcache` or `-decode` or `/decode` or `verifyctl`.
- Why it matters: Certutil is a certificate tool, but its URL cache and decode options are widely abused to download payloads and unpack base64-encoded files without extra tooling.
- Known false positives: Administrators decoding certificates or checking revocation lists.

## CMD-004 · Mshta remote or inline script

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1218.005](https://attack.mitre.org/techniques/T1218/005/) System Binary Proxy Execution: Mshta.
- Tactics: Stealth.
- Matches: event 1; `image_name` is `mshta.exe`; `command_line` contains `http://` or `https://` or `javascript:` or `vbscript:`.
- Why it matters: Mshta running an HTA from a URL or an inline javascript or vbscript expression executes code through a signed Windows binary, a frequent way to slip past allow-listing.
- Known false positives: Legacy internal tools built as HTML applications.

## CMD-005 · Regsvr32 remote scriptlet

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1218.010](https://attack.mitre.org/techniques/T1218/010/) System Binary Proxy Execution: Regsvr32.
- Tactics: Stealth.
- Matches: event 1; `image_name` is `regsvr32.exe`; `command_line` contains `/i:http` or `-i:http` or `scrobj.dll`.
- Why it matters: Regsvr32 loading a scriptlet from a URL or through scrobj.dll runs remote script code with a signed Windows binary and leaves little on disk.
- Known false positives: Old software that registers scriptlets during installation.

## CMD-006 · Recovery inhibited

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery.
- Tactics: Impact.
- Matches any of:
  - event 1; `image_name` is `vssadmin.exe`; `command_line` contains `delete` and `shadows`.
  - event 1; `image_name` is `wmic.exe`; `command_line` contains `shadowcopy` and `delete`.
  - event 1; `image_name` is `wbadmin.exe`; `command_line` contains `delete` and `catalog`.
  - event 1; `image_name` is `bcdedit.exe`; `command_line` contains `recoveryenabled` and `no`.
- Why it matters: Deleting shadow copies or backup catalogs, or turning off boot recovery, removes the usual ways to restore files and is a common step just before ransomware encryption.
- Known false positives: Backup software or administrators removing old shadow copies.

## CMD-007 · Event log cleared

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1685.005](https://attack.mitre.org/techniques/T1685/005/) Disable or Modify Tools: Clear Windows Event Logs.
- Tactics: Defense Impairment.
- Matches any of:
  - event 1; `image_name` is `wevtutil.exe`; `command_line` contains ` cl ` or ` clear-log `.
  - event 1; `command_line_full` contains `clear-eventlog`.
- Why it matters: Clearing Windows event logs destroys the record of earlier activity; outside planned maintenance it is a strong sign that someone is covering their tracks.
- Known false positives: Planned log maintenance and lab or image resets.

## CRD-001 · LSASS memory access

- Kind: event; severity: high; needs events: 10.
- ATT&CK: [T1003.001](https://attack.mitre.org/techniques/T1003/001/) OS Credential Dumping: LSASS Memory.
- Tactics: Credential Access.
- Matches: event 10; `target_image` ends with `\lsass.exe`; `granted_access` is `0x1010` or `0x1410` or `0x1438` or `0x143a` or `0x1f0fff` or `0x1f1fff` or `0x1f2fff` or `0x1f3fff` or `0x1fffff`.
- Unless:
  - `source_image_name` is `csrss.exe` or `wininit.exe` or `services.exe` or `svchost.exe` or `wmiprvse.exe` or `lsm.exe` or `msmpeng.exe`.
- Why it matters: Opening LSASS with memory-read access is how credential dumpers extract passwords and hashes. The exclusions are system processes that do this routinely; they can be bypassed by renaming a tool.
- Known false positives: Security, backup or monitoring agents that are not on the exclusion list.

## CRD-002 · LSASS dump via command line

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1003.001](https://attack.mitre.org/techniques/T1003/001/) OS Credential Dumping: LSASS Memory.
- Tactics: Credential Access.
- Matches any of:
  - event 1; `command_line` contains `comsvcs` and `minidump`.
  - event 1; `image_name` is `procdump.exe` or `procdump64.exe`; `command_line` contains `lsass`.
- Why it matters: The comsvcs.dll MiniDump export and ProcDump pointed at LSASS write the process memory to a file, from which credentials can be extracted offline.
- Known false positives: Administrators taking LSASS dumps on purpose for troubleshooting.

## GR-001 · Office-descended process connected out

- Kind: graph; severity: high; needs events: 1, 3.
- ATT&CK: [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File.
- Tactics: Execution.
- Logic: A process made an outbound connection (event 3, initiated) and one of its ancestors, up to the first anchor, is an Office application from the LIN-001 list. The finding is on the connecting process.
- Why it matters: A process started below an Office application made an outbound connection; documents that launch helpers which then reach the network are a common phishing delivery pattern.
- Known false positives: Office add-ins or helpers launched from documents that reach the network.

## GR-002 · Discovery burst

- Kind: graph; severity: medium; needs events: 1.
- ATT&CK: [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery; [T1082](https://attack.mitre.org/techniques/T1082/) System Information Discovery; [T1016](https://attack.mitre.org/techniques/T1016/) System Network Configuration Discovery; [T1087](https://attack.mitre.org/techniques/T1087/) Account Discovery; [T1482](https://attack.mitre.org/techniques/T1482/) Domain Trust Discovery; [T1057](https://attack.mitre.org/techniques/T1057/) Process Discovery.
- Tactics: Discovery.
- Logic: Three or more different discovery tools (whoami, systeminfo, nltest, net, net1, ipconfig, quser, tasklist, netstat, arp, route, nslookup) started by one parent within 120 seconds. The finding is on the parent.
- Why it matters: Three or more different discovery tools started by one parent within two minutes look like hands-on or scripted reconnaissance rather than routine use.
- Known false positives: Inventory or logon scripts that run several discovery tools.

## GR-003 · Dropped file later executed

- Kind: graph; severity: medium; needs events: 1, 11.
- ATT&CK: [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer.
- Tactics: Command and Control.
- Logic: A file written by event 11 is later started by event 1 on the same host (same normalized path). The finding is on the started process; the most recent earlier write is reported as the creator.
- Why it matters: A file written to disk and then started as a process on the same host is how dropped payloads usually begin.
- Known false positives: Installers and updaters that download and then run their own binaries.

## GR-004 · Active process with no creation record

- Kind: graph; severity: info; needs events: 1.
- ATT&CK: none (context signal).
- Tactics: none.
- Logic: A process with no creation record (a ghost seen through its own activity) made network connections or created files. The finding is on the ghost. Anchors with a verified path and the path-less System and Registry processes are skipped; a ghost that matches an anchor by name alone is still flagged.
- Why it matters: A process used the network or created files, but its creation was never recorded, so its origin is unknown.
- Known false positives: Logs that start after the process did, so its creation is missing.

## INJ-001 · Remote thread created in another process

- Kind: event; severity: medium; needs events: 8.
- ATT&CK: [T1055](https://attack.mitre.org/techniques/T1055/) Process Injection.
- Tactics: Stealth, Privilege Escalation.
- Matches: event 8.
- Unless:
  - `source_image_name` is `csrss.exe` or `wininit.exe` or `services.exe` or `svchost.exe` or `lsass.exe` or `smss.exe`.
- Why it matters: Starting a thread inside another process is the core of most code-injection techniques. The exclusions are system processes that do this routinely; they can be bypassed by renaming a tool.
- Known false positives: Debuggers, accessibility tools and some security products.

## LIN-001 · Office application spawned an interpreter

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File.
- Tactics: Execution.
- Matches: event 1; `parent_image_name` is `winword.exe` or `excel.exe` or `powerpnt.exe` or `outlook.exe` or `msaccess.exe` or `mspub.exe` or `onenote.exe`; `image_name` is `cmd.exe` or `powershell.exe` or `pwsh.exe` or `wscript.exe` or `cscript.exe` or `mshta.exe` or `rundll32.exe` or `regsvr32.exe`.
- Why it matters: Office documents that start a shell, script host or proxy-execution binary are a classic phishing payload; Office rarely needs to launch interpreters in normal use.
- Known false positives: Office add-ins or macros that legitimately start scripts or helpers.

## LIN-002 · Script host spawned a shell

- Kind: event; severity: medium; needs events: 1.
- ATT&CK: [T1059.005](https://attack.mitre.org/techniques/T1059/005/) Command and Scripting Interpreter: Visual Basic; [T1059.007](https://attack.mitre.org/techniques/T1059/007/) Command and Scripting Interpreter: JavaScript.
- Tactics: Execution.
- Matches: event 1; `parent_image_name` is `wscript.exe` or `cscript.exe` or `mshta.exe`; `image_name` is `cmd.exe` or `powershell.exe` or `pwsh.exe`.
- Why it matters: VBScript, JScript and HTA files that open a command shell or PowerShell often belong to a downloader chain; legitimate scripts seldom need a second interpreter.
- Known false positives: Logon or maintenance scripts written in VBScript or JScript.

## LIN-003 · WMI provider host spawned a shell

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1047](https://attack.mitre.org/techniques/T1047/) Windows Management Instrumentation.
- Tactics: Execution.
- Matches: event 1; `parent_image_name` is `wmiprvse.exe`; `image_name` is `cmd.exe` or `powershell.exe` or `pwsh.exe`.
- Why it matters: A shell started by the WMI provider host usually means a command was run remotely or by a WMI subscription, both common for lateral movement and persistence.
- Known false positives: Systems management tools that run commands through WMI.

## LOC-001 · Execution from a user-writable staging path

- Kind: event; severity: low; needs events: 1.
- ATT&CK: none (context signal).
- Tactics: Execution.
- Matches: event 1; `image` contains `\users\public\` or `\appdata\local\temp\` or `\windows\temp\` or `\downloads\` or `\$recycle.bin\` or `\perflogs\`.
- Why it matters: Programs started from Public, Temp, Downloads, the recycle bin or PerfLogs are often freshly dropped tools. This is a context signal: installers also run from these places.
- Known false positives: Installers, updaters and portable tools run from Temp or Downloads.

## LOC-002 · System binary name outside system directories

- Kind: event; severity: high; needs events: 1.
- ATT&CK: [T1036.005](https://attack.mitre.org/techniques/T1036/005/) Masquerading: Match Legitimate Resource Name or Location.
- Tactics: Stealth.
- Matches: event 1; `image_name` is `svchost.exe` or `lsass.exe` or `csrss.exe` or `services.exe` or `smss.exe` or `wininit.exe` or `winlogon.exe` or `spoolsv.exe` or `taskhostw.exe`.
- Unless:
  - `image` starts with `c:\windows\system32\` or `c:\windows\syswow64\` or `c:\windows\winsxs\`.
- Why it matters: Core Windows process names only ever run from the system directories; the same name anywhere else is a classic masquerade meant to blend into a process list.
- Known false positives: Third-party software that ships a binary with the same name.

## NET-001 · Proxy-execution binary made a network connection

- Kind: event; severity: high; needs events: 3.
- ATT&CK: [T1218](https://attack.mitre.org/techniques/T1218/) System Binary Proxy Execution; [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer.
- Tactics: Stealth, Command and Control.
- Matches: event 3; `image_name` is `rundll32.exe` or `regsvr32.exe` or `mshta.exe` or `certutil.exe` or `msbuild.exe` or `installutil.exe` or `cmstp.exe`; `initiated` is `true`.
- Why it matters: Signed Windows binaries that can run arbitrary code rarely need to open outbound connections; when they do, they are often fetching or talking to a payload.
- Known false positives: Signed components hosted by rundll32 that contact update servers.

## PER-001 · Registry Run key set

- Kind: event; severity: medium; needs events: 13.
- ATT&CK: [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder.
- Tactics: Persistence.
- Matches: event 13; `target_object` contains `\currentversion\run\` or `\currentversion\runonce\` or `\currentversion\policies\explorer\run\`.
- Why it matters: Values under the Run and RunOnce keys start a program at every logon, the most common way for malware to survive a reboot.
- Known false positives: Applications and updaters that add themselves to Run keys.

## PER-002 · Scheduled task created

- Kind: event; severity: medium; needs events: 1.
- ATT&CK: [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task.
- Tactics: Persistence, Execution.
- Matches: event 1; `image_name` is `schtasks.exe`; `command_line` contains `/create` or `-create`.
- Why it matters: A scheduled task created from the command line can run a payload on a timer or at logon; attackers use it for persistence and for delayed execution.
- Known false positives: Installers and IT management that create scheduled tasks.

## PER-003 · Service created

- Kind: event; severity: medium; needs events: 1, 13.
- ATT&CK: [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Create or Modify System Process: Windows Service.
- Tactics: Persistence.
- Matches any of:
  - event 1; `image_name` is `sc.exe`; `command_line` contains `create`.
  - event 1; `command_line_full` contains `new-service`.
  - event 13; `target_object` contains `\currentcontrolset\services\`; `target_object` ends with `\imagepath`.
- Why it matters: A new service runs its binary with system rights at every boot; creating one from the command line or by writing a service ImagePath is a common persistence step.
- Known false positives: Driver and service installers, and IT tooling.

## PER-004 · File written to a Startup folder

- Kind: event; severity: medium; needs events: 11.
- ATT&CK: [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder.
- Tactics: Persistence.
- Matches: event 11; `target_filename` contains `\start menu\programs\startup\`.
- Why it matters: Anything placed in a Startup folder runs when the user logs on; dropping a file there is a simple and common persistence method.
- Known false positives: Shortcuts placed in Startup by users or installers.

## Attribution

Technique and tactic IDs and names are from MITRE ATT&CK®, <https://attack.mitre.org/>. ATT&CK is a registered trademark of The MITRE Corporation and is used here under the ATT&CK terms of use. Lineage is not affiliated with or endorsed by MITRE.
