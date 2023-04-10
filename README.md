# IOC_Grabber

### Prerequisite  
  
On linux machine for ``Hash-Parser`` and ``Munin`` part ``git`` is necessary.  
*Debian*
```
apt install git
```
*Arch-linux*
```
pacman -S git
```
## Installation
* *Linux*  
```
git clone --recurse-submodules https://github.com/Oni-kuki/IOC_Grabber
```  
* *Windows*  
However for the file ``IOC_Grabber.ps1`` it's possible that you are obliged to work in Offline in an optics of Forensic so you can obviously use other way to make it available on your machine.  
Otherwise you can also install ``git`` on Windows.  
you can easily do this with the ``chocolatey`` package manager  
https://chocolatey.org/  
~~You can also use the compiled file provided~~  
## **IOC_Grabber**

Just a small module to get all interesting IOC's on Windows
and analyze the hashes of different file types like .exe, .sys, .dll to compare them with different API's from :
Virustotal, HybridAnalysis, Any.Run, URLhaus, MISP, CAPE, Malshare, Valhalla, Hashlookup.  
(For some tools it's just a matter of checking the URL, of course).  
https://github.com/Oni-kuki/IOC_Grabber/blob/main/IOC_Grabber.ps1  
* Be careful to have as many indicators as possible run the script with administrator rights  
```
./IOC_Grabber.ps1
```
### Hash-Parser | Parsing of Hash
----
For hash analysis, I wrote a small tool, to extract the md5, Sha1 and Sha256 hashes from any file type.  
https://github.com/Oni-kuki/Hash-Parser  
```
./Hash-Parser.sh <filename>
```

### **Munin** | For queries to different hash comparators
----  
For queries to different hash comparators  
I just forked the Munin tool that can be found here: https://github.com/Neo23x0/munin  
**I salute Neo23x0 and the other contributors of this tool, you did a great job, thanks for that !**  
To use it, you just have to use the munin.py script by specifying the file name of the hashes you have previously generated  
Attention, it may be necessary to install the different prerequisites of the munin tool, so for that you have to run the command :  
```
pip3 install -r requirements
```  
in the munin folder where the requirements file is located.  
https://github.com/Oni-kuki/munin  
```
./munin.py <Hashes_filename>
```
