#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: Hash-Parser.sh.sh <filename>"
  exit 1
fi
# Parse IOC.txt for Hashes
  awk ' {print $2 }' "$1" > Hashes.txt && sed '1,3d' Hashes.txt -i
 