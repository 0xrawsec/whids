#!/bin/bash

if [ -f "$1" ]
then
    xq '.' "$1" | python genstruct.py - | gofmt
else
    echo "Usage: $(basename $0) SYSMON_SCHEMA_XML"
fi