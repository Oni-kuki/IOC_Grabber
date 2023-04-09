#!/bin/bash

echo "  ##   ##                    ###               ###### ";
echo "  ##   ##                     ##                ##  ## ";
echo "  ##   ##   ####     #####    ##                ##  ##   ####    ######    #####    ####    ###### ";
echo "  #######      ##   ##        #####   ######    #####       ##    ##  ##  ##       ##  ##    ##  ## ";
echo "  ##   ##   #####    #####    ##  ##            ##       #####    ##       #####   ######    ## ";
echo "  ##   ##  ##  ##        ##   ##  ##            ##      ##  ##    ##           ##  ##        ## ";
echo "  ##   ##   #####   ######   ###  ##           ####      #####   ####     ######    #####   #### ";
echo "  more Easy with that script                    Oni-kuki                                         ";

now=`date +%Y-%m-%d_%H-%M-%S`
if [ -z "$1" ]; then
  echo "Usage: Hash-Parser.sh <filename>"
  exit 1
fi
# Check if file exists
if [ -e "$1" ]; then
  # Check if file is empty
  if [ -s "$1" ]; then
    # Check if file contains hashes
    if grep -E -o "([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})" "$1" > /dev/null; then
      echo "Hashes Found"
      grep -E -o "([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})" "$1" > Hashes_"$now".txt
      echo "Hashes Written To File Hashes_$now.txt"
    else
      echo "No Hashes in file (MD5, SHA1, SHA256)"
    fi
  else
    echo "File Of Hashes Is Empty"
  fi
else
  echo "File Of Hashes Not Found"
fi