#!/bin/bash

set -e

# go to repo root directory
ROOT=`git rev-parse --show-toplevel`
cd ${ROOT}

# documentation related
TITLE="EDR commands documentation"
br="\\"
indent=""


echo "# $TITLE"
echo 

cat << EOF
This page documents the EDR specific commands endpoints can run.In addition to all the commands documented$br
below, **any** other binary present on the endpoint can be executed, whether by absolute path or without if$br
the binary is present in the PATH environment variable.

**IMPORTANT:** paths in command examples may contain escape sequences (Windows paths for instances).$br
When such path is used inside JSON escape characters needs to be escaped once again (to be JSON valid).$br
For instance if one wants to execute \`tasklist\` command from an absolute path the command would have to$br
be encoded as such \`C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\tasklist.exe\`

EOF

echo

echo "## Index"
while read -r line
do
    command=$(jq -r ".name" <<<$line)
    echo "* [$command](#$command)"
done < <(grep -RhPazo --include="*.go" '(?s)(?<!#)@command.*?\}' ./  | sed 's/@command:/\n/g' | tr -d '\0' | jq -c '.')
echo

while read -r line
do
    command=$(jq -r ".name" <<<$line)
    desc=$(jq -r ".description" <<<$line)
    help=$(jq -r ".help" <<<$line)
    example=$(jq -r ".example" <<<$line)

    echo -e "## $command\n"
    echo -e "$indent**Description:** $desc\n"
    echo "$indent**Help:** $help"
    echo
    if [[ $example != "null" ]]
    then
        echo "$indent**Example:** $example"
        echo
    fi
    echo

done < <(grep -RhPazo --include="*.go" '(?s)(?<!#)@command.*?\}' ./  | sed 's/@command:/\n/g' | tr -d '\0' | jq -c '.')