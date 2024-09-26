#!/bin/sh

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 filesdir searchstr"
fi

filesdir=$1
searchstr=$2

if [ ! -d "$filesdir" ]; then
    echo: "Directory does not exist"
    exit 1
fi

echo "Searching for '$searchstr' in '$filesdir'"

matching_files=$(find "$filesdir" -type f | wc -l)

total_lines=$(grep -r "$searchstr" "$filesdir" | wc -l)

if [ "$matching_files" -gt 0 ]; then
    echo "The number of files are $matching_files and the number of matching lines are $total_lines"
else
    echo "No matches found"
fi