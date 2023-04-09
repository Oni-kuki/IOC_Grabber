# creation of the IOC-Grabber folder on the desktop
mkdir "C:\Users\$env:UserName\Desktop\IOC-Grabber"

# capture the running processes and save them in a csv file
Get-Process | Select-Object Name, Path, CommandLine | Export-Csv -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber\ioc.csv"

# Capture the network connections and save them in a csv file
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | Export-Csv -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber\netTCPco.csv" 

# Research of the files with the extension .exe, .dll, .sys and save them in a csv file with their hash
Get-ChildItem -Path C:\ -Recurse -Include *.exe,*.dll,*.sys | Get-FileHash | Where-Object { $_.Algorithm -in @('MD5', 'SHA1', 'SHA256') } | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\known_malware.txt"

# Net connections
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -notlike '192.168.*' } | Out-File 'C:\Users\$env:UserName\Desktop\IOC-Grabber\network_connections.txt'

# HKLM registar key # taskbar / last visited mru / Command executed in the run dialog box / bam / dam 
Get-ChildItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'| Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\HKLM_malicious_registry_keys.txt"

# HKCU registar key # taskbar / last visited mru / Command executed in the run dialog box / Run keys / RunOnce keys / RunOnceEx keys / AppCompatCache / FeatureUsage \ micro,camera ...usage / USERAssist  
Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Run*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\','HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\','HKCU:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache','HKCU:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage', 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore', "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\HKCU_malicious_registry_keys.txt"
# Recherche des processus malveillants en cours d'exécution
Get-Process | Where-Object { $_.Path -ne $null -and $_.Path -notlike 'C:\Windows*' } | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\running_malware_processes.txt"

#Amcache, Jumplist, Prefetch , USage Monitor,
Get-ChildItem -Path "$Env:WinDir\AppCompat\Programs\Amcache.hve", "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations", "$Env:WinDir\Prefetch", "$Env:WinDir\System32\SRU\SRUDB.dat" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Amcache_Jumplist_Prefetch_USageMonitor.txt"

# File and Folder Opening ## OpenSaveMRU / RecentDocs / LAStVisitedPidlMRU (same of previous) / SHortcut (lnk) / shellbags and ShellbagsMRU / Jumplist 
Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMR*', 'HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMR*', "$env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent\", 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Bag*', "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations", "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\File_and_Folder_Opening.txt"

# Deleted items and file exitence ## Windows search database / worldwheel query / typed path / thumbcache / recycle bin
Get-ChildItem -Path "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex" , 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuer*', 'HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPath*', "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explore", "C:\$Recycle.Bin" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Deleted_items_and_file_exitence.txt"


#System information # OS / ComputerName / system BOOT & autostart / last shutdown
Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'HKLM:\SYSTEM\Setup\BuildUpdat*', 'HKLM:SYSTEM\CurrentControlSet\Control\ComputerName\ComputerNam*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run*', 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run*', 'HKLM:\SYSTEM\CurrentControlSet\Services', 'HKLM:\SYSTEM\CurrentControlSet\Control\Window*' | out-file "C:\Users\$env:UserName\Desktop\IOC-Grabber\System_information.txt"
#If Start value is set to 0x02, then service application will start at boot (0x00 for drivers)

# Account usage ## User profile list
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Account_usage.txt"
# Cloud storage ## OneDrive / Google Drive / Dropbox / Box

# Network Activity and Physical Location ## Network activity / 
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Network_Activity.txt"
# System Ressource Usage monitor ## SRUM
<# Network Profile NameType values:
- 6 (0x06) = Wired
- 23 (0x17) = VPN
- 71 (0x47) = Wireless
- 243 (0xF3) = Mobile Broadband#>

# External Device/USB Usage ## USB / mounted devices 
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB', 'HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI', 'HKLM:\SYSTEM\CurrentControlSet\Enum\HID', 'HKLM:\SYSTEM\MountedDevice*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2' | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\External_Device_USB_Usage.txt"

#System Event 
Get-WinEvent -FilterHashtable @{Logname='System'; id=20001,20003} | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\System_evtx.txt"
#• Event IDs 20001, 20003 – Plug and Play driver install attempted

#Security Event
Get-WinEvent -FilterHashtable @{Logname='Security'; id=4663,4656,6416} | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\security_evtx.txt"
<#
• 4663 – Attempt to access removable storage object (Security log)
• 4656 – Failure to access removable storage object (Security log)
• 6416 – A new external device was recognized on system (Security log)
• Security log events are dependent on system audit settings
#>
#Connection Locatiojn first time
Get-Content -Path "$Env:WinDir\inf\setupapi.dev.log" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Connection_timestamps.txt"
# Connextion times
Get-WinEvent -Path "$Env:WinDir\System32\winevt\logs\Microsoft-Windows-Partition*" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Connection_timestamps.txt"


# Browser history ## Firefox / Chrome / Edge
#Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles", "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default", "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Browser_history.txt"
# History and dowload necessity to use sqlite3 portable
#Get-ChildItem -Path 