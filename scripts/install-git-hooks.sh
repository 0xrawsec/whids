#/bin/bash

ROOT=`git rev-parse --show-toplevel`
cp ./scripts/hooks/* ${ROOT}/.git/hooks/