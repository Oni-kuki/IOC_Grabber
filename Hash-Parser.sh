awk ' {print $2 }' IOC.txt > Hashes.txt | sed '1,3d' Hashes.txt -i
