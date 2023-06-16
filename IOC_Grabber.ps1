Write-Host "
          _          _             _                               _              _           _                   _               _               _            _      
         /\ \       /\ \         /\ \                             /\ \           /\ \        / /\                / /\            / /\            /\ \         /\ \    
         \ \ \     /  \ \       /  \ \                           /  \ \         /  \ \      / /  \              / /  \          / /  \          /  \ \       /  \ \   
         /\ \_\   / /\ \ \     / /\ \ \                         / /\ \_\       / /\ \ \    / / /\ \            / / /\ \        / / /\ \        / /\ \ \     / /\ \ \  
        / /\/_/  / / /\ \ \   / / /\ \ \                       / / /\/_/      / / /\ \_\  / / /\ \ \          / / /\ \ \      / / /\ \ \      / / /\ \_\   / / /\ \_\ 
       / / /    / / /  \ \_\ / / /  \ \_\                     / / / ______   / / /_/ / / / / /  \ \ \        / / /\ \_\ \    / / /\ \_\ \    / /_/_ \/_/  / / /_/ / / 
      / / /    / / /   / / // / /    \/_/                    / / / /\_____\ / / /__\/ / / / /___/ /\ \      / / /\ \ \___\  / / /\ \ \___\  / /____/\    / / /__\/ /  
     / / /    / / /   / / // / /             ___________    / / /  \/____ // / /_____/ / / /_____/ /\ \    / / /  \ \ \__/ / / /  \ \ \__/ / /\____\/   / / /_____/   
 ___/ / /__  / / /___/ / // / /________  ___/__________/\  / / /_____/ / // / /\ \ \  / /_________/\ \ \  / / /____\_\ \  / / /____\_\ \  / / /______  / / /\ \ \     
/\__\/_/___\/ / /____\/ // / /_________\/__________    \ \/ / /______\/ // / /  \ \ \/ / /_       __\ \_\/ / /__________\/ / /__________\/ / /_______\/ / /  \ \ \    
\/_________/\/_________/ \/____________/\____\/    \____\/\/___________/ \/_/    \_\/\_\___\     /____/_/\/_____________/\/_____________/\/__________/\/_/    \_\/                                                                                                                                                                                                                                                                                  
more Easy with that script                    Oni-kuki                                         " -ForegroundColor Red 

# folder creation on the desktop to store the artifacts
if (!(Test-Path -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber")) {
    New-Item -ItemType Directory -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber"
}
# username of the user who launched the script
$username = $env:UserName

# check if the script is run with administrator privileges
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($admin) {
    # check if the script is run with administrator privileges
    Write-Host "You are already administrator ! " -ForegroundColor green
}
else {
    # if the user is not administrator, ask him to run the script with administrator privileges if not, the script will be executed normally
    throw "it is necessary to run the script with administrator privileges !"
}
function Capturing {
    capture_process
    capture_network
    capture_Hash
    capture_Netconnections
    capture_HKLM
    capture_HKCU
    capture_listProcess
    capture_listServices
    capture_FilesOpened
    capture_itemsFiles
    capture_sysInfo
    capture_accountUsage
    capture_netActivity
    capture_extDevice
    capture_sysEvent
    capture_secEvent
    capture_co_location
    capture_co_timestamps
    Hash_Artifacts
}

function capture_process{ 
# capture the running processes and save them in a csv file
Write-Host "Capture the running processes and save them in a csv file..." 
Get-Process | Select-Object Name, Path, CommandLine | Export-Csv -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber\ioc.csv"
write-host "Process Captured" -ForegroundColor Green
}

function capture_network{
# Capture the network connections and save them in a csv file
Write-Host "Capture the network connections and save them in a csv file..."
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | Export-Csv -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber\netTCPco.csv" 
write-host "Network connections Captured" -ForegroundColor Green
}

function capture_Hash {
# Research of the files with the extension .exe, .dll, .sys and save them in a csv file with their hash
Write-Host "Research of the files with the extension .exe, .dll, .sys and save them in a csv file with their hash..."
Get-ChildItem -Path C:\ -Recurse -Include *.exe,*.dll,*.sys | Get-FileHash | Where-Object { $_.Algorithm -in @('MD5', 'SHA1', 'SHA256') } | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\known_malware.txt"
write-host "Files with the extension .exe, .dll, .sys Captured" -ForegroundColor Green
}

function capture_Netconnections {
# Net connections
Write-Host "Net connections..."
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -notlike '192.168.*' } | Out-File 'C:\Users\$env:UserName\Desktop\IOC-Grabber\network_connections.txt'
write-host "Net connections Captured" -ForegroundColor Green
}

function capture_HKLM {
# HKLM registar key # taskbar / last visited mru / Command executed in the run dialog box / bam / dam 
write-host "HKLM registar key, taskbar, last visited mru, command executed in run dialog box, bam and dam reg..."
Get-ChildItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'| Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\HKLM_malicious_registry_keys.txt"
write-host "HKLM registar key, taskbar, last visited mru, command executed in run dialog box, bam and dam reg Captured" -ForegroundColor Green
}

function capture_HKCU {
# HKCU registar key # taskbar / last visited mru / Command executed in the run dialog box / Run keys / RunOnce keys / RunOnceEx keys / AppCompatCache / FeatureUsage \ micro,camera ...usage / USERAssist  
write-host "HKCU registar key, taskbar, last visited mru, command executed in run dialog box, Run keys, RunOnce keys, RunOnceEx keys, AppCompatCache, FeatureUsage, micro,camera ...usage and USERAssist reg..."
Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Run*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\','HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\','HKCU:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache','HKCU:\NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage', 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore', "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\HKCU_malicious_registry_keys.txt"
write-host "HKCU registar key, taskbar, last visited mru, command executed in run dialog box, Run keys, RunOnce keys, RunOnceEx keys, AppCompatCache, FeatureUsage, micro,camera ...usage and USERAssist reg Captured" -ForegroundColor Green
}

function capture_listProcess {
# captures the list of processes running on the system, filters the processes that have a valid file path not equal to null
Write-Host "captures the list of processes running on the system, filters the processes that have a valid file path not equal to null..."
Get-Process | Where-Object { $_.Path -ne $null -and $_.Path -notlike 'C:\Windows*' } | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\running_malware_processes.txt"
write-host "List of processes running on the system Captured" -ForegroundColor Green
}

function capture_listServices{
#Amcache, Jumplist, Prefetch , USage Monitor,
Write-Host "Amcache, Jumplist, Prefetch , USage Monitor..."
Get-ChildItem -Path "$Env:WinDir\AppCompat\Programs\Amcache.hve", "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations", "$Env:WinDir\Prefetch", "$Env:WinDir\System32\SRU\SRUDB.dat" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Amcache_Jumplist_Prefetch_USageMonitor.txt"
write-host "Amcache, Jumplist, Prefetch , USage Monitor Captured" -ForegroundColor Green
}

function capture_FilesOpened{
# File and Folder Opening ## OpenSaveMRU / RecentDocs / LAStVisitedPidlMRU (same of previous) / SHortcut (lnk) / shellbags and ShellbagsMRU / Jumplist
Write-Host "File and Folder Opening, OpenSaveMRU, RecentDocs, LAStVisitedPidlMRU, SHortcut, shellbags and ShellbagsMRU, Jumplist..."
Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMR*', 'HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMR*', "$env:USERPROFILE\AppData\Roaming\Microsoft\Office\Recent\", 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Bag*', "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations", "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\File_and_Folder_Opening.txt"
write-host "File and Folder Opening, OpenSaveMRU, RecentDocs, LAStVisitedPidlMRU, SHortcut, shellbags and ShellbagsMRU, Jumplist Captured" -ForegroundColor Green
}

function capture_itemsFiles{
# Deleted items and file exitence ## Windows search database / worldwheel query / typed path / thumbcache / recycle bin
Write-Host "Deleted items and file exitence, Windows search database, worldwheel query, typed path, thumbcache, recycle bin..."
Get-ChildItem -Path "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\GatherLogs\SystemIndex" , 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuer*', 'HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPath*', "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explore", "C:\$Recycle.Bin" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Deleted_items_and_file_exitence.txt"
write-host "Deleted items and file exitence, Windows search database, worldwheel query, typed path, thumbcache, recycle bin Captured" -ForegroundColor Green
}

function capture_sysInfo{
#System information # OS / ComputerName / system BOOT & autostart / last shutdown
Write-Host "System information, OS, ComputerName, system BOOT & autostart, last shutdown..."
Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'HKLM:\SYSTEM\Setup\BuildUpdat*', 'HKLM:SYSTEM\CurrentControlSet\Control\ComputerName\ComputerNam*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run*', 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run*', 'HKLM:\SYSTEM\CurrentControlSet\Services', 'HKLM:\SYSTEM\CurrentControlSet\Control\Window*' | out-file "C:\Users\$env:UserName\Desktop\IOC-Grabber\System_information.txt"
write-host "System information, OS, ComputerName, system BOOT & autostart, last shutdown Captured" -ForegroundColor Green
#If Start value is set to 0x02, then service application will start at boot (0x00 for drivers)
}

function capture_accountUsage{
# Account usage ## User profile list
Write-Host "Account usage, User profile list..."
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Account_usage.txt"
write-host "Account usage, User profile list Captured" -ForegroundColor Green
# Cloud storage ## OneDrive / Google Drive / Dropbox / Box
}

function capture_netActivity{
# Network Activity and Physical Location ## Network activity /
Write-Host "Network Activity and Physical Location, Network activity..." 
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Network_Activity.txt"
write-host "Network Activity and Physical Location, Network activity Captured" -ForegroundColor Green
}

# System Ressource Usage monitor ## SRUM
<# Network Profile NameType values:
- 6 (0x06) = Wired
- 23 (0x17) = VPN
- 71 (0x47) = Wireless
- 243 (0xF3) = Mobile Broadband#>

function capture_extDevice{
# External Device/USB Usage ## USB / mounted devices 
Write-Host "External Device/USB Usage, USB, mounted devices..."
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB', 'HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI', 'HKLM:\SYSTEM\CurrentControlSet\Enum\HID', 'HKLM:\SYSTEM\MountedDevice*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2' | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\External_Device_USB_Usage.txt"
write-host "External Device/USB Usage, USB, mounted devices Captured" -ForegroundColor Green
}

function capture_sysEvent{
#System Event 
#Create System directory if it doesn't exist, and then create the files for each severity level + all events file
Get-WinEvent -FilterHashtable @{Logname='System'; id=20001,20003} | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\System_evtx.txt"
write-host "System Event Captured" -ForegroundColor Green
#• Event IDs 20001, 20003 – Plug and Play driver install attempted
}

function capture_secEvent{
#Security Event
#Create Security directory if it doesn't exist, and then create the files for each severity level + all events file
if (!(Test-Path -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber\Security-events")) {
    New-Item -ItemType Directory -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber\Security-events"
}
$CRITICALIDs = "4618","4649","4719","4765","4766","4794","4897","4964","5124","1102"
$MEDIUMIDs = "4621","4675","4692","4693","4706","4713","4714","4715","4716","4724","4727","4735","4737","4739","4754","4755","4764","4764","4780","4816","4865","4866","4867","4868","4870","4882","4885","4890","4892","4896","4906","4907","4908","4912","4960","4961","4962","4963","4965","4976","4977","4978","4983","4984","5027","5028","5029","5030","5035","5037","5038","5120","5121","5122","5123","5376","5377","5453","5480","5483","5484","5485","5827","5828","6145","6273","6274","6275","6276","6277","6278","6279","6280","24586","24592","24593","24594"
$LOWIDs = "4608","4609","4610","4611","4612","4614","4615","4616","4622","4624","4625","4634","4646","4647","4648","4650","4651","4652","4653","4654","4655","4656","4657","4658","4659","4660","4661","4662","4663","4664","4665","4666","4667","4668","4670","4671","4672","4673","4674","4688","4689","4690","4691","4694","4695","4696","4697","4698","4699","4700","4701","4702","4704","4705","4707","4709","4710","4711","4712","4717","4718","4720","4722","4723","4725","4726","4728","4729","4730","4731","4732","4733","4734","4738","4740","4741","4742","4743","4744","4745","4746","4747","4748","4749","4750","4751","4752","4753","4756","4757","4758","4759","4760","4761","4762","4767","4768","4769","4770","4771","4772","4774","4775","4776","4777","4778","4779","4781","4782","4783","4784","4785","4786","4787","4788","4789","4790","4793","4800","4801","4802","4803","4864","4869","4871","4872","4873","4874","4875","4876","4877","4878","4879","4880","4881","4883","4884","4886","4887","4888","4889","4891","4893","4894","4895","4898","4902","4904","4905","4909","4910","4928","4929","4930","4931","4932","4933","4934","4935","4936","4937","4944","4945","4946","4947","4948","4949","4950","4951","4952","4953","4954","4956","4957","4958","4979","4980","4981","4982","4985","5024","5025","5031","5032","5033","5034","5039","5040","5041","5042","5043","5044","5045","5046","5047","5048","5050","5051","5056","5057","5058","5059","5060","5061","5062","5063","5064","5065","5066","5067","5068","5069","5070","5125","5126","5127","5136","5137","5138","5139","5140","5141","5152","5153","5154","5155","5156","5157","5158","5159","5378","5440","5441","5442","5443","5444","5446","5447","5448","5449","5450","5451","5452","5456","5457","5458","5459","5460","5461","5462","5463","5464","5465","5466","5467","5468","5471","5472","5473","5474","5477","5479","5632","5633","5712","5888","5889","5890","6008","6144","6272","24577","24578","24579","24580","24581","24582","24583","24584","24588","24595","24621","5049","5478"

Write-Host "Grabbing all Security events..."
Get-WinEvent -FilterHashtable @{Logname='Security'} | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Security-events\Security_evtx_ALL.txt"
Write-Host "all Security events grabbed..." -ForegroundColor Green
Write-Host "Grabbing Critical Security events..."
Get-WinEvent -FilterHashtable @{Logname='Security'} | Where-Object { $CRITICALIDs -contains $_.Id } | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Security-events\Security_evtx_CRITICAL.txt"
Write-Host "Critical Security events grabbed..." -ForegroundColor Green
Write-Host "Grabbing Medium Security events..."
Get-WinEvent -FilterHashtable @{Logname='Security'} | Where-Object { $MEDIUMIDs -contains $_.Id } | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Security-events\Security_evtx_MEDIUM.txt"
Write-Host "Medium Security events grabbed..." -ForegroundColor Green
Write-Host "Grabbing Low Security events..."
Get-WinEvent -FilterHashtable @{Logname='Security'} | Where-Object { $LOWIDs -contains $_.Id } | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Security-events\Security_evtx_LOW.txt"
Write-Host "Low Security events grabbed..." -ForegroundColor Green
}
<#
• 4663 – Attempt to access removable storage object (Security log)
• 4656 – Failure to access removable storage object (Security log)
• 6416 – A new external device was recognized on system (Security log)
• Security log events are dependent on system audit settings
#>
function capture_co_location {
#Connection Location first time
Write-Host "Grabbing Connection Location..."
Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Microsoft\Windows\UsrClass.dat" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Connection_location.txt"
Get-Content -Path "$Env:WinDir\inf\setupapi.dev.log" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Connection_timestamps.txt"
Write-Host "Connection Location grabbed..." -ForegroundColor Green
}

function capture_co_timestamps {
# Connextion times
Write-Host "Grabbing Connection timestamps..."
Get-WinEvent -Path "$Env:WinDir\System32\winevt\logs\Microsoft-Windows-Partition*" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Connection_timestamps.txt"
Write-Host "Connection timestamps grabbed..." -ForegroundColor Green
}
# Browser history ## Firefox / Chrome / Edge
#Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles", "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default", "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default" | Out-File "C:\Users\$env:UserName\Desktop\IOC-Grabber\Browser_history.txt"
# History and dowload necessity to use sqlite3 portable
#Get-ChildItem -Path

function Hash_Artifacts {
# Sum of artefacts for integrity check (MD5, SHA1, SHA256)
Write-Host "Hash of artifacts in progress..."
$dateTime = Get-Date -Format yyyyMMdd-HHmmss
$fileName = "Control_sum_of_artefacts_$dateTime.txt"
Get-ChildItem -Path "C:\Users\$env:UserName\Desktop\IOC-Grabber" -Recurse -Include *.txt | Get-FileHash | Where-Object { $_.Algorithm -in @('MD5', 'SHA1', 'SHA256') } | Out-File "C:\Users\$env:UserName\Desktop\$fileName"
Write-Host "Hashing Done !" -ForegroundColor Green
Write-Host "All Done!, you can find the artefacts on your desktop, here: C:\Users\$env:UserName\Desktop\IOC-Grabber, Good Luck!"
}
# Call the function 
Capturing
