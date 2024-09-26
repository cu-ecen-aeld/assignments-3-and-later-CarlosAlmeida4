#!/bin/sh

if [ "$#" -ne 2 ]; then
    echo "Usage: writefile writestr"
    exit 1
fi

writefile=$1
writestr=$2

dirpath=$(dirname "$writefile")

mkdir -p "$dirpath"
if [ "$?" -ne 0 ]; then
    echo "Failed to created directory $dirpath"
    exit 1
fi

echo "$writestr" > "$writefile"
if [ "$?" -ne 0 ]; then
    echo "Could not write to file $writefile"
    exit 1
fi
