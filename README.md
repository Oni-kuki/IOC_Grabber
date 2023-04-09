# IOC_Grabber
Just a small module to get all interesting IOCs on Windows
and analyze the hashes of different file types like .exe, .sys, .dll to compare them with different APIs from :
Virustotal, HybridAnalysis, Any.Run, URLhaus, MISP, CAPE, Malshare, Valhalla, Hashlookup (for some tools it's just a matter of checking the URL, of course).
https://github.com/Oni-kuki/IOC_Grabber/blob/main/IOC_Grabber.ps1

## Parsing of Hash
For hash analysis, I wrote a small tool, to extract the md5, Sha1 and Sha256 hashes from any file type on which the grep search can be performed.
https://github.com/Oni-kuki/Hash-Parser 

## For queries to different hash comparators
I just forked the Munin tool that can be found here: https://github.com/Neo23x0/munin I salute Neo23x0 and the other contributors of this tool, you did a great job, thanks for that!
To use it, you just have to use the munin.py script by specifying the file name of the hashes you have previously generated
Attention, it may be necessary to install the different prerequisites of the munin tool, so for that you have to run the command :
``pip3 install -r requirements`` in the munin folder where the requirements file is located.
https://github.com/Oni-kuki/munin 
