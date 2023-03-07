# Registry
- `HKEY_CURRENT_USER`: Contains the root of the configuration information for the user who is currently logged on,  user's folders, screen colors, and Control Panel settings, `HKCU`
- `HKEY_USERS`: Contains all the actively loaded user profiles on the computer, `HKU`
- `HKEY_LOCAL_MACHINE`: Contains configuration information particular to the computer (for any user), `HKLM`
- `HKEY_CLASSES_ROOT`:  contains file name extension associations and COM class registration information such as ProgIDs, CLSIDs, and IIDs. It is primarily intended for compatibility with the registry in 16-bit Windows
- `HKEY_CURRENT_CONFIG`: Contains information about the hardware profile that is used by the local computer at system startup. 

- Access using `regedit.exe`
- Located in `C:\Windows\System32\Config`
  - DEFAULT (mounted on HKEY_USERS\DEFAULT)
  - SAM (mounted on HKEY_LOCAL_MACHINE\SAM)
  - SECURITY (mounted on HKEY_LOCAL_MACHINE\Security)
  - SOFTWARE (mounted on HKEY_LOCAL_MACHINE\Software)
  - SYSTEM (mounted on HKEY_LOCAL_MACHINE\System)
- Also in `C:\Users\<username>`
  - NTUSER.DAT (mounted on HKEY_CURRENT_USER when a user logs in)
  - USRCLASS.DAT (mounted on HKEY_CURRENT_USER\Software\CLASSES)
- `C:\Windows\AppCompat\Programs\Amcache.hve`
- Data acquisition using `KAPE`, `FTK Imager`.
- Forensics Tools 
  - `Registry Viewer` https://www.exterro.com (looks like its paid version now)
  - `Zimmerman's Registry Explorer` https://ericzimmerman.github.io/#!index.md
  - `RegRipper` (takes hive as input) https://github.com/keydet89/RegRipper3.0

## Common system information information
  - OS Version `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
  - Boot Up Control Set infos in Inside the `HKLM\SYSTEM\CurrentControlSet` `SYSTEM\ControlSet001` Control set that machine booted with. `SYSTEM\ControlSet002`  the last known good configuration. Also We can see which control set is being used by looking at registry value`SYSTEM\Select\Current` and `SYSTEM\Select\LastKnownGood`
  - Computer name in `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`
  - Timezone info in `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
  - Network interfaces are listed with unique GUID in `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`. There will info in each GUID field in the right pane
  - Past networks that the computer connected to is in either `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged`  or `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed`
  - Info on comamnds/programs that runs when user logs on `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce` `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` `SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run` and `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
  - Information about users `SYSTEM\CurrentControlSet\Services`
  - Sam HIVE user information `SAM\Domains\Account\Users`. user account information, login information, and group information. Users RID with `10x` is user generated.

## Usage of Files/Folders
  - Recently open files `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
  - Recently open word files info `NTUSER.DAT\Software\Microsoft\Office\VERSION`
  - Specific extensions `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf`
  - Shell bats (layouts) for specific users `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags` `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`
  - Location to where recent file was saved `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU` `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`. This info is used by the dailouge box that prompts to save file.
  - Windows path the user has visited `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`1
 
 ## Evidence of Execution
  - Program launched by user, not cli `NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count`
  - ShimCache (AppCompatCache ) Application launched in application compability `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCach`. Parse using different tool `AppCompatCacheParser.exe --csv <path to save output> -f <path to SYSTEM hive for data parsing> -c <control set to parse>`.
  - AmCache `C:\Windows\appcompat\Programs\Amcache.hve` `Amcache.hve\Root\File\{Volume GUID}\`
  - BAM/DAM Background Activity Monitor and Desktop Activity Monitor `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` `SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`

## External Devices/USB device forensics
  - USB devices plugged into the system `SYSTEM\CurrentControlSet\Enum\USBSTOR` `SYSTEM\CurrentControlSet\Enum\USB`.  vendor id, product id, and version of the USB device 
  - First and last time connected `SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####`
  - Device Name of the connected Drive `SOFTWARE\Microsoft\Windows Portable Devices\Devices`
