#!/usr/bin/bash

search=("0xrawsec")

for s in ${search[*]}
do
    while read -r dep
    do
        echo "go get -u $dep"
        go get -u $dep
    done< <(go list -f '{{ join .Deps  "\n"}}' ./... | grep "$s" | cut -d '/' -f 1-3 | sort -u)
done
