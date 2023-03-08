`File System for organizaing data`
# File Allocation Table (FAT)
## Clusters:
 - A cluster is a basic storage unit of the FAT file system. Each file stored on a storage device can be considered a group of clusters containing bits of information.
## Directory:
 - A directory contains information about file identification, like file name, starting cluster, and filename length.
## File Allocation Table:
 - The File Allocation Table is a linked list of all the clusters. It contains the status of the cluster and the pointer to the next cluster in the chain.
## the bits that make up a file are stored in `clusters`. All the filenames on a file system, their starting clusters, and their lengths are stored in `directories`. 
And the location of each cluster on the disk is stored in the `File Allocation Table`

- The number of these clusters depends on the number of bits used to address the cluster. Thus Fat 12/16/32
- ExFat for MicroSD, without NTFS security

# New Technology File System (NTFS)
 - Journaling, logs of changes made, stored in $LOGFILE in the volume's root directory, helps recover from crashes or data movement due to defragmentation
 - access controls that define the owner of a file/directory and permissions for each user
 - keeps track of changes made to a file using a feature called Volume Shadow Copies.
 - Alternate Data Streams
 - Master File Table is much more organized 
 - `$MFT` is the first record in the volume. The Volume Boot Record (VBR) points to the cluster where it is located. $MFT stores information about the clusters where all other objects present on the volume are located. This file contains a directory of all the files present on the volume.
 - `$LOGFILE`stores the transactional logging of the file system. It helps maintain the integrity of the file system in the event of a crash.
 - `$UsnJrnl` the Update Sequence Number (USN) Journal. It is present in the `$Exten`d record. It contains information about all the files that were changed in the file system and the reason for the change. It is also called the change journal.
 - `**MFT Explorer**` Tool from https://ericzimmerman.github.io/#!index.md to help explore. `MFTECmd.exe -f <path-to-$MFT-file ex: C:/$MFT> --csv <path-to-save-results-in-csv>`. 
 - Tip, can view the output file with `EzViewer`. Also make sure u see hidden files in C:

# Recover deleted files
 - Use `autopsy`, deleted files will have red `x` mark on them, also create disk image and stuffs.

# Evidence of Execution
  - Prefetch file contains info of recently executed applications as well `C:\Windows\Prefetch` with .pf extension. Prefetch is used to quicky open recent application
  - Use PEcmd.exe from Eric Zimmerman's tools  `PECmd.exe -f <path-to-Prefetch-files> --csv <path-to-save-csv>` or `PECmd.exe -d <path-to-Prefetch-directory> --csv <path-to-save-csv>`
  - In windows 10, timeline information, info about recently used application info can be found in `C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\{randomfolder}\ActivitiesCache.db`.
  - Use `Eric Zimmerman's WxTCmd.exe`, `WxTCmd.exe -f <path-to-timeline-file> --csv <path-to-save-csv>`
  - Jumplists, Contains information about recently opened files by applications in taskbar. Location in `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`.
  - use Eric Zimmerman's `JLECmd.exe`. `JLECmd.exe -f <path-to-Jumplist-file> --csv <path-to-save-csv>`
